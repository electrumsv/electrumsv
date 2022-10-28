import msvcrt
import os
import sys

def write_to_log_file(log_filename: str, text: str) -> None:
    # We use the locking of the same part of the file to gain an exclusive lock over the whole
    # file.
    with open(log_filename, "a") as log_file:
        msvcrt.locking(log_file.fileno(), msvcrt.LK_RLCK, 1)
        log_file.write(text + os.linesep)
        msvcrt.locking(log_file.fileno(), msvcrt.LK_UNLCK, 1)


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

