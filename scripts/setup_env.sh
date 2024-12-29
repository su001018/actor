DIR=$(dirname $BASH_SOURCE)
export SCRIPT_HOME=$(realpath $DIR)
export PROJECT_HOME=$(realpath $DIR/../)
export TOOLS_HOME=$(realpath $PROJECT_HOME/tools/)
export LINUX_HOME=$(realpath $PROJECT_HOME/linux/)

export QEMU_HOME=$TOOLS_HOME/qemu