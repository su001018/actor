DIR=$(dirname $BASH_SOURCE)
export SCRIPT_HOME=$(realpath $DIR)
export PROJECT_HOME=$(realpath $DIR/../)
export TOOLS_HOME=$(realpath $PROJECT_HOME/tools/)
export LINUX_HOME=$(realpath $PROJECT_HOME/linux/)

export QEMU_HOME=$TOOLS_HOME/qemu

VMLINUX=$LINUX_HOME/vmlinux

if [ ! -f $VMLINUX ]; then
	echo "Build kernel first!"
	exit 1
fi

echo "[*]VMLINUX: $(realpath $VMLINUX)"

HYPEADDR=$(objdump -d $VMLINUX | grep "sys_hypercall" -A 100 -m 1 | grep nop | cut -d':' -f1 | head -n1)
HYPEADDR='0x'$HYPEADDR

echo "[*]HYPEADDR: $HYPEADDR"

echo "[*]QEMU_HOME:" $QEMU_HOME
pushd $QEMU_HOME>/dev/null


mkdir -p build
pushd build

../configure --target-list=x86_64-softmmu

CFLAGS="-D_HYPERCALL_ADDR=$HYPEADDR" make -j`nproc`

popd
popd>/dev/null