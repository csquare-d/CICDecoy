package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cicdecoy/cli/pkg/db"
	"github.com/cicdecoy/cli/pkg/k8s"
	"github.com/cicdecoy/cli/pkg/nats"
	"github.com/cicdecoy/cli/pkg/output"
)

var (
	cfgFile    string
	kubeconfig string
	kubeCtx    string
	namespace  string
	verbose    bool
	jsonOutput bool
	noColor    bool

	// Shared clients — initialized lazily
	kube     *k8s.Client
	natsConn *nats.Client
	dbConn   *db.Client
	printer  *output.Printer
)

var rootCmd = &cobra.Command{
	Use:   "cicdecoy",
	Short: "CI/CDecoy — Deception as Code platform CLI",
	Long: `CI/CDecoy manages deception assets on Kubernetes.

Deploy honeypots, monitor attacker sessions, query threat intelligence,
and export IOCs — all from the terminal.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		printer = output.NewPrinter(jsonOutput, noColor)
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ~/.cicdecoy.yaml)")
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "path to kubeconfig")
	rootCmd.PersistentFlags().StringVar(&kubeCtx, "context", "", "kubernetes context")
	rootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "", "target namespace")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colored output")

	// Register all subcommands
	rootCmd.AddCommand(
		newDeployCmd(),
		newDestroyCmd(),
		newStatusCmd(),
		newFleetCmd(),
		newSessionsCmd(),
		newIntelCmd(),
		newValidateCmd(),
		newLogsCmd(),
		newRotateCmd(),
		newProfileCmd(),
		newConfigCmd(),
	)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, _ := os.UserHomeDir()
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigName(".cicdecoy")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvPrefix("CICDECOY")
	viper.AutomaticEnv()
	viper.ReadInConfig() // ignore error — config file is optional
}

// getKubeClient returns a lazily-initialized kubernetes client.
func getKubeClient() (*k8s.Client, error) {
	if kube != nil {
		return kube, nil
	}
	path := kubeconfig
	if path == "" {
		path = viper.GetString("kubeconfig")
	}
	if path == "" {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, ".kube", "config")
		}
	}
	var err error
	kube, err = k8s.NewClient(path, kubeCtx, namespace)
	return kube, err
}

// getNATSClient returns a lazily-initialized NATS client.
func getNATSClient() (*nats.Client, error) {
	if natsConn != nil {
		return natsConn, nil
	}
	url := viper.GetString("nats.url")
	if url == "" {
		// Auto-discover from k8s service
		kc, err := getKubeClient()
		if err != nil {
			return nil, fmt.Errorf("cannot discover NATS: %w", err)
		}
		url, err = kc.DiscoverNATSURL()
		if err != nil {
			return nil, fmt.Errorf("NATS not found in cluster: %w", err)
		}
	}
	var err error
	natsConn, err = nats.NewClient(url)
	return natsConn, err
}

// getDBClient returns a lazily-initialized TimescaleDB client.
func getDBClient() (*db.Client, error) {
	if dbConn != nil {
		return dbConn, nil
	}
	dsn := viper.GetString("db.dsn")
	if dsn == "" {
		kc, err := getKubeClient()
		if err != nil {
			return nil, fmt.Errorf("cannot discover DB: %w", err)
		}
		dsn, err = kc.DiscoverDBDSN()
		if err != nil {
			return nil, fmt.Errorf("TimescaleDB not found in cluster: %w", err)
		}
	}
	var err error
	dbConn, err = db.NewClient(dsn)
	return dbConn, err
}
