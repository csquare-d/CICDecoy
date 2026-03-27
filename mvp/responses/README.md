# Response Databases

Place captured response database JSON files here.

To build a response database from a real system:

    python tools/capture_responses.py \
        --local \
        --profile dev-workstation \
        --output responses/ubuntu-22.04-dev.json

Or capture from a remote system:

    python tools/capture_responses.py \
        --host 192.168.1.100 \
        --user admin \
        --key ~/.ssh/id_rsa \
        --output responses/ubuntu-22.04-dev.json

The high-fidelity engine loads all .json files from this directory
automatically at startup.
