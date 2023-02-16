#!/bin/bash
set -e

#we flush the ARP cache because outdated ARP entries may let tests fail
sudo ip -s -s neigh flush all

if [ $# -ge 1 ]; then
    TASK=$1
else
    TASK=all
fi

case $TASK in
    test_rfs_ip)
        export RUST_LOG="tcp_lib=info,test_tcp_proxy=debug,e2d2=info"
        export RUST_BACKTRACE=1
        executable=`cargo test $2 $3 $4 --no-run --message-format=json --test test_tcp_proxy | jq -r 'select((.profile.test == true) and (.target.name == "test_tcp_proxy")) | .filenames[]'`
        echo $executable
        echo ./tests/test_rfs_ip.toml > tests/toml_file.txt
        sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" $executable --nocapture
        ;;
    test_rfs_ip.2)
        export RUST_LOG="tcp_lib=info,test_tcp_proxy=info,e2d2=info"
        export RUST_BACKTRACE=1
        executable=`cargo test $2 --no-run --message-format=json --test test_tcp_proxy | jq -r 'select((.profile.test == true) and (.target.name == "test_tcp_proxy")) | .filenames[]'`
        echo $executable
        echo ./tests/test_rfs_ip.2.toml > tests/toml_file.txt
        sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" $executable --nocapture
        ;;
    test_rfs_port)
        export RUST_LOG="tcp_lib=debug,test_tcp_proxy=debug,e2d2=info,netfcts=debug"
        export RUST_BACKTRACE=1
        executable=`cargo test $2 $3 $4 --no-run --message-format=json --test test_tcp_proxy | jq -r 'select((.profile.test == true) and (.target.name == "test_tcp_proxy")) | .filenames[]'`
        echo $executable
        echo ./tests/test_rfs_port.toml > tests/toml_file.txt
        sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" $executable --nocapture
        ;;
    timeout)
        export RUST_BACKTRACE=1
        export RUST_LOG="tcp_lib=debug,timeout=debug,e2d2=info"
        executable=`cargo test $2 $3 $4 --no-run --message-format=json --test timeout | jq -r 'select((.profile.test == true) and (.target.name == "timeout")) | .filenames[]'`
        echo $executable
        echo ./tests/timeout.toml > tests/toml_file.txt
        sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" $executable --nocapture
        ;;
    timeout.2)
        export RUST_BACKTRACE=1
        export RUST_LOG="tcp_lib=info,timeout=info,e2d2=info"
        executable=`cargo test $2 $3 $4 --no-run --message-format=json --test timeout | jq -r 'select((.profile.test == true) and (.target.name == "timeout")) | .filenames[]'`
        echo $executable
        echo ./tests/timeout.2.toml > tests/toml_file.txt
        sudo -E env "PATH=$PATH" $executable --nocapture
        ;;
    client_syn_fin)
        export RUST_LOG="tcp_lib=info,client_syn_fin=info,e2d2=info"
        export RUST_BACKTRACE=1
        executable=`cargo test $2 $3 $4 --no-run --message-format=json --test client_syn_fin | jq -r 'select((.profile.test == true) and (.target.name == "client_syn_fin")) | .filenames[]'`
        echo $executable
        echo ./tests/client_syn_fin.toml > tests/toml_file.txt
        sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" $executable --nocapture
        ;;
    client_syn_fin.2)
        export RUST_LOG="tcp_lib=info,client_syn_fin=info,e2d2=info"
        executable=`cargo test $2 --no-run --message-format=json --test client_syn_fin | jq -r 'select((.profile.test == true) and (.target.name == "client_syn_fin")) | .filenames[]'`
        echo $executable
        echo ./tests/client_syn_fin.2.toml > tests/toml_file.txt
        sudo -E env "PATH=$PATH" $executable --nocapture
        ;;
    test_as_client)
        export RUST_LOG="tcp_lib=debug,e2d2=debug", RUST_BACKTRACE=1
        executable=`cargo test $2 $3 $4 --no-run --message-format=json --test test_as_client | jq -r 'select((.profile.test == true) and (.target.name == "test_as_client")) | .filenames[]'`
        echo $executable
        echo ./tests/test_gen.toml > tests/toml_file.txt
        sudo -E env "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" $executable --nocapture
        ;;
    test_as_server)
        export RUST_LOG="tcp_lib=info,e2d2=info", RUST_BACKTRACE=1
        executable=`cargo test $2 $3 $4 --no-run --message-format=json --test test_as_server | jq -r 'select((.profile.test == true) and (.target.name == "test_as_server")) | .filenames[]'`
        echo $executable
        echo ./tests/test_gen.toml > tests/toml_file.txt
        sudo -E env "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" $executable --nocapture
        ;;
    macswap)
        export RUST_LOG="tcp_lib=info,macswap=info,e2d2=info", RUST_BACKTRACE=1
        executable=`cargo test $2 $3 $4 --no-run --message-format=json --test macswap | jq -r 'select((.profile.test == true) and (.target.name == "macswap")) | .filenames[]'`
        echo $executable
        echo ./tests/macswap.toml > tests/toml_file.txt
        sudo -E env "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" $executable --nocapture
        ;;
    test_as_client.2)
        export RUST_LOG="tcp_lib=info,e2d2=info", RUST_BACKTRACE=1
        executable=`cargo test $2 --no-run --message-format=json --test test_as_client | jq -r 'select((.profile.test == true) and (.target.name == "test_as_client")) | .filenames[]'`
        echo $executable
        echo ./tests/test_gen.2.toml > tests/toml_file.txt
        sudo -E env "PATH=$PATH; LD_LIBRARY_PATH=$LD_LIBRARY_PATH" $executable --nocapture
        ;;
    test_as_server.2)
        export RUST_LOG="tcp_lib=info,e2d2=info", RUST_BACKTRACE=1
        executable=`cargo test $2 --no-run --message-format=json --test test_as_server | jq -r 'select((.profile.test == true) and (.target.name == "test_as_server")) | .filenames[]'`
        echo $executable
        echo ./tests/test_gen.2.toml > tests/toml_file.txt
        sudo -E env "PATH=$PATH" $executable --nocapture
        ;;
    macswap.2)
        export RUST_LOG="tcp_lib=info,macswap=info,e2d2=info", RUST_BACKTRACE=1
        executable=`cargo test $2 --no-run --message-format=json --test macswap | jq -r 'select((.profile.test == true) and (.target.name == "macswap")) | .filenames[]'`
        echo $executable
        echo ./tests/macswap.2.toml > tests/toml_file.txt
        sudo -E env "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" $executable --nocapture
        ;;
    all)
        ./test.sh test_as_client $2 $3 $4
        ./test.sh test_as_server $2 $3 $4
        ;;
esac




