DIR=$(dirname $BASH_SOURCE)
PROJECT_HOME=$(realpath $DIR/../../)
SYZ_HOME=$PROJECT_HOME/src/github.com/google/syzkaller/

# 文件前缀、大小和路径定义
FUZZER_PREFIX="ivshmemfilefuzzer-vm"
SCHEDULER_PREFIX="ivshmemfilescheduler-vm"
SIZE="512"
PERMISSIONS=666
TARGET_PATH="/dev/shm"

DEBUG_FILE="$PROJECT_HOME/out/workdir/debug.txt"
CORPUS_FILE="$PROJECT_HOME/out/workdir/corpus.db"
UAF_CORPUS_FILE="$PROJECT_HOME/out/workdir/uaf_corpus.db"
# 函数定义：创建文件
create_file() {
    local FILE="$1"
    if [ ! -e "$FILE" ]; then
        echo "Creating $FILE..."
        dd if=/dev/zero of="$FILE" bs=1M count="$SIZE" status=progress
        chmod $PERMISSIONS "$FILE"
        echo "$FILE created with permissions $PERMISSIONS."
    else
        echo "$FILE already exists. Skipping creation."
    fi
}

# 使用循环创建文件
for i in {0..7}; do
    FUZZER_FILE="${TARGET_PATH}/${FUZZER_PREFIX}${i}"

    create_file "$FUZZER_FILE"

done
for i in {0..7}; do

    SCHEDULER_FILE="${TARGET_PATH}/${SCHEDULER_PREFIX}${i}"

    create_file "$SCHEDULER_FILE"
done


params=("-config" "actor.config")
DUMP=false
NAME=""

# 遍历所有传入的参数
for (( i=1; i<=$#; i++ )); do
    arg="${!i}"
    case "$arg" in
        "-fdebug")
            params+=("-fdebug")
            ;;
        "-sdebug")
            params+=("-sdebug")
            ;;
        "-race")
            params+=("-race")
            ;;
        "-dump")
            DUMP=true
            ;;
        "-name")
            # 检查是否还有下一个参数
            if (( i + 1 <= $# )); then
                ((i++))
                NAME="${!i}"
            else
                echo "Error: -name option requires an argument." >&2
                exit 1
            fi
            ;;
        *)
            # 处理未知参数
            echo "Unknown option: $arg" >&2
            exit 1
            ;;
    esac
done

# 如果 NAME 不为空，将其添加到 params 数组中
if [ -n "$NAME" ]; then
    params+=("-name" "$NAME")
fi

# 检查 debug.txt 文件是否存在，如果存在则删除
if [ -f "$DEBUG_FILE" ]; then
    rm "$DEBUG_FILE"
fi
# 重新创建 debug.txt 文件
touch "$DEBUG_FILE"

if $DUMP; then
    rm "$CORPUS_FILE"
    rm "$UAF_CORPUS_FILE"
    $SYZ_HOME/bin/syz-manager "${params[@]}" > "$DEBUG_FILE" 2>&1
else
    $SYZ_HOME/bin/syz-manager "${params[@]}"
fi