package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"github.com/cicdecoy/cli/pkg/k8s"
)

// ── Deploy ────────────────────────────────────────────

func newDeployCmd() *cobra.Command {
	var (
		files   []string
		dir     string
		dryRun  bool
		wait    bool
		timeout string
	)

	cmd := &cobra.Command{
		Use:   "deploy [manifest|dir]",
		Short: "Deploy decoys from YAML manifests",
		Long: `Deploy one or more decoy manifests to the cluster.

Manifests are validated, sorted by dependency order
(Profiles → Templates → HoneyTokens → Decoys → Fleets),
and applied via the Kubernetes API.`,
		Example: `  cicdecoy deploy config/dev-decoy.yaml
  cicdecoy deploy -d manifests/ --wait
  cicdecoy deploy -f decoy1.yaml -f decoy2.yaml --dry-run`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kc, err := getKubeClient()
			if err != nil {
				return err
			}

			// Collect manifest paths
			paths := files
			if len(args) > 0 {
				paths = append(paths, args[0])
			}
			if dir != "" {
				dirPaths, err := collectManifests(dir)
				if err != nil {
					return err
				}
				paths = append(paths, dirPaths...)
			}

			if len(paths) == 0 {
				return fmt.Errorf("no manifests specified — use positional arg, -f, or -d")
			}

			// Load and parse
			docs, err := loadManifests(paths)
			if err != nil {
				return err
			}

			// Validate
			allErrors := validateDocs(docs)
			if len(allErrors) > 0 {
				for _, e := range allErrors {
					printer.Error(e)
				}
				return fmt.Errorf("validation failed with %d error(s)", len(allErrors))
			}

			// Sort by dependency order
			sortByKind(docs)

			// Apply
			applied, failed := 0, 0
			for _, doc := range docs {
				name := doc.GetName()
				kind := doc.GetKind()

				if dryRun {
					printer.Info("[dry-run] Would apply %s/%s", kind, name)
					applied++
					continue
				}

				printer.Info("Applying %s/%s...", kind, name)
				if err := kc.ApplyDecoy(doc); err != nil {
					printer.Error("  Failed: %v", err)
					failed++
				} else {
					printer.Success("  Applied %s/%s", kind, name)
					applied++
				}
			}

			printer.Info("\n%d applied, %d failed", applied, failed)

			if wait && !dryRun && failed == 0 {
				printer.Info("Waiting for decoys to become ready...")
				return kc.WaitForDecoys(docs, timeout)
			}

			if failed > 0 {
				return fmt.Errorf("%d manifest(s) failed to apply", failed)
			}
			return nil
		},
	}

	cmd.Flags().StringArrayVarP(&files, "file", "f", nil, "manifest file(s)")
	cmd.Flags().StringVarP(&dir, "directory", "d", "", "directory of manifests")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be deployed")
	cmd.Flags().BoolVar(&wait, "wait", false, "wait for decoys to become ready")
	cmd.Flags().StringVar(&timeout, "timeout", "120s", "wait timeout")

	return cmd
}

// ── Destroy ───────────────────────────────────────────

func newDestroyCmd() *cobra.Command {
	var (
		all     bool
		cascade bool
		force   bool
	)

	cmd := &cobra.Command{
		Use:   "destroy <name>",
		Short: "Remove decoys",
		Example: `  cicdecoy destroy ssh-dmz-01 -n decoys-production
  cicdecoy destroy --all -n decoys-staging
  cicdecoy destroy --all --cascade --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !all && len(args) == 0 {
				return fmt.Errorf("specify a decoy name or --all")
			}

			kc, err := getKubeClient()
			if err != nil {
				return err
			}

			if !force {
				target := "all decoys"
				if len(args) > 0 {
					target = args[0]
				}
				printer.Warn("This will destroy %s in namespace %s", target, kc.Namespace())
				if !printer.Confirm("Continue?") {
					return nil
				}
			}

			if all {
				return kc.DestroyAllDecoys(cascade)
			}
			return kc.DestroyDecoy(args[0], cascade)
		},
	}

	cmd.Flags().BoolVar(&all, "all", false, "remove all decoys in namespace")
	cmd.Flags().BoolVar(&cascade, "cascade", false, "also remove associated resources")
	cmd.Flags().BoolVar(&force, "force", false, "skip confirmation")

	return cmd
}

// ── Rotate ────────────────────────────────────────────

func newRotateCmd() *cobra.Command {
	var (
		all      bool
		strategy string
	)

	cmd := &cobra.Command{
		Use:   "rotate <name>",
		Short: "Trigger identity rotation for a decoy",
		Example: `  cicdecoy rotate ssh-dmz-01
  cicdecoy rotate --all -n decoys-production`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !all && len(args) == 0 {
				return fmt.Errorf("specify a decoy name or --all")
			}

			kc, err := getKubeClient()
			if err != nil {
				return err
			}

			if all {
				printer.Info("Triggering rotation for all decoys...")
				return kc.RotateAllDecoys(strategy)
			}

			printer.Info("Rotating %s...", args[0])
			return kc.RotateDecoy(args[0], strategy)
		},
	}

	cmd.Flags().BoolVar(&all, "all", false, "rotate all decoys")
	cmd.Flags().StringVar(&strategy, "strategy", "", "override rotation strategy")

	return cmd
}

// ── Manifest Helpers ──────────────────────────────────

func collectManifests(dir string) ([]string, error) {
	var paths []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			paths = append(paths, path)
		}
		return nil
	})
	return paths, err
}

func loadManifests(paths []string) ([]k8s.DecoyResource, error) {
	var docs []k8s.DecoyResource
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", p, err)
		}

		// Handle multi-document YAML
		parts := strings.Split(string(data), "\n---")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" || part == "---" {
				continue
			}

			var raw map[string]interface{}
			if err := yaml.Unmarshal([]byte(part), &raw); err != nil {
				return nil, fmt.Errorf("parsing %s: %w", p, err)
			}

			apiVersion, _ := raw["apiVersion"].(string)
			if !strings.HasPrefix(apiVersion, "cicdecoy.io/") {
				continue
			}

			doc, err := k8s.ParseDecoyResource([]byte(part), p)
			if err != nil {
				return nil, fmt.Errorf("parsing resource in %s: %w", p, err)
			}
			docs = append(docs, doc)
		}
	}
	return docs, nil
}

// sortByKind ensures dependency order: Profiles → Templates → HoneyTokens → Decoys → Fleets
func sortByKind(docs []k8s.DecoyResource) {
	order := map[string]int{
		"DecoyProfile":  0,
		"DecoyTemplate": 1,
		"HoneyToken":    2,
		"Decoy":         3,
		"DecoyFleet":    4,
	}
	sort.SliceStable(docs, func(i, j int) bool {
		return order[docs[i].GetKind()] < order[docs[j].GetKind()]
	})
}

func validateDocs(docs []k8s.DecoyResource) []string {
	var errs []string
	for _, doc := range docs {
		errs = append(errs, doc.Validate()...)
	}
	return errs
}
