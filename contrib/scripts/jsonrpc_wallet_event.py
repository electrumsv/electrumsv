from io import TextIOWrapper
import os
import platform
import sys

if platform.system() == "Windows":
    import msvcrt
    def lock_file(log_file: TextIOWrapper) -> None:
        msvcrt.locking(log_file.fileno(), msvcrt.LK_RLCK, 1)
    def unlock_file(log_file: TextIOWrapper) -> None:
        msvcrt.locking(log_file.fileno(), msvcrt.LK_UNLCK, 1)
else:
    import fcntl
    def lock_file(log_file: TextIOWrapper) -> None:
        fcntl.lockf(log_file.fileno(), fcntl.LOCK_EX)
    def unlock_file(log_file: TextIOWrapper) -> None:
        fcntl.lockf(log_file.fileno(), fcntl.LOCK_UN)


def write_to_log_file(log_filename: str, text: str) -> None:
    # We use the locking of the same part of the file to gain an exclusive lock over the whole
    # file.
    with open(log_filename, "a") as log_file:
        lock_file(log_file)
        log_file.write(text + os.linesep)
        unlock_file(log_file)


def main() -> None:
    # The first entry in the argument list is the script path.
    full_script_path = sys.argv[0]
    script_path = os.path.dirname(full_script_path)
    # Place the log file in the same directory.
    log_filename = os.path.join(script_path, "tx.log")

    if len(sys.argv) != 2:
        write_to_log_file(log_filename, "ERROR incorrect number of arguments")
        return

    write_to_log_file(log_filename, f"VALID {sys.argv[1]}")


if __name__ == "__main__":
    main()
