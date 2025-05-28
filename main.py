import argparse
import os
import math
import logging
import stat
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Column, Table
from rich.text import Text

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command line interface.
    """
    parser = argparse.ArgumentParser(description="Calculates the entropy of permission settings across a system or directory.")
    parser.add_argument("path", help="Path to the directory to analyze.")
    parser.add_argument("-e", "--exclude", help="Exclude files/directories matching this pattern (glob).", default=None)
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively analyze subdirectories.")
    parser.add_argument("-t", "--threshold", type=float, default=0.0, help="Threshold for highlighting high entropy files. (Default: 0.0)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress informational output.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    return parser.parse_args()


def calculate_entropy(data):
    """
    Calculates the entropy of a dataset.
    """
    if not data:
        return 0.0

    entropy = 0.0
    data_length = len(data)
    counts = {}
    for x in data:
        counts[x] = counts.get(x, 0) + 1

    for count in counts.values():
        probability = float(count) / data_length
        entropy -= probability * math.log2(probability)

    return entropy


def get_permissions(filepath):
    """
    Gets the permission bits for a file.
    """
    try:
        st = os.stat(filepath)
        return stat.S_IMODE(st.st_mode)  # Extracts permission bits
    except OSError as e:
        logging.error(f"Error getting permissions for {filepath}: {e}")
        return None


def analyze_permissions(path, exclude_pattern=None, recursive=False, threshold=0.0, console=None):
    """
    Analyzes permissions for files in a directory and its subdirectories, calculating entropy.

    Args:
        path (str): The path to the directory to analyze.
        exclude_pattern (str, optional): A glob pattern for excluding files. Defaults to None.
        recursive (bool, optional): Whether to recursively analyze subdirectories. Defaults to False.
        threshold (float, optional): Entropy threshold for highlighting. Defaults to 0.0.
        console (Console, optional): Rich Console object for output. Defaults to None.
    """

    permission_data = []
    file_paths = []
    count = 0
    high_entropy_files = []

    if console is None:
        console = Console()

    try:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Path not found: {path}")

        if os.path.isfile(path):
            # Handle single file case
            perm = get_permissions(path)
            if perm is not None:
                permission_data.append(perm)
                file_paths.append(path)
                count = 1
        else:
            # Traverse the directory
            for root, _, files in os.walk(path):
                if not recursive and root != path:
                    continue  # Skip subdirectories if not recursive

                for file in files:
                    filepath = os.path.join(root, file)

                    if exclude_pattern and Path(filepath).match(exclude_pattern):
                        logging.debug(f"Skipping {filepath} due to exclusion pattern.")
                        continue

                    perm = get_permissions(filepath)
                    if perm is not None:
                        permission_data.append(perm)
                        file_paths.append(filepath)
                        count += 1
    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        return
    except OSError as e:
        logging.error(f"Error during file system traversal: {e}")
        return
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return

    if not permission_data:
        console.print("[yellow]No files found or permissions could be read.[/yellow]")
        return

    entropy = calculate_entropy(permission_data)

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("File Path", style="dim")
    table.add_column("Permissions", style="green")
    table.add_column("Entropy", style="cyan")

    for filepath, perm in zip(file_paths, permission_data):
         file_entropy = calculate_entropy([perm])  # Entropy for single file.  Always 0 unless doing more complex things

         if file_entropy > threshold and threshold > 0:  #Only highlight if threshold > 0, prevents always highlighting.
             table.add_row(Text(filepath, style="red"), str(oct(perm)), str(file_entropy))
             high_entropy_files.append(filepath)
         else:
             table.add_row(filepath, str(oct(perm)), str(file_entropy))


    console.print(table)

    console.print(f"\n[bold]Total Files Analyzed:[/bold] {count}")
    console.print(f"[bold]Permission Entropy:[/bold] {entropy:.4f}")
    if high_entropy_files:
        console.print("[bold red]High Entropy Files (>{:.4f}):[/bold red]".format(threshold))
        for file in high_entropy_files:
            console.print(f"  - [red]{file}[/red]")



def main():
    """
    Main function to execute the permission entropy analyzer.
    """
    args = setup_argparse()

    if not os.path.exists(args.path):
        print(f"Error: Path '{args.path}' does not exist.")
        sys.exit(1)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)  # Set logging to debug if verbose flag is set
        logging.debug("Verbose mode enabled.")

    console = Console() #Rich Console for output.

    if not args.quiet:
        console.print("[bold blue]Starting Permission Entropy Analysis...[/bold blue]")


    analyze_permissions(args.path, args.exclude, args.recursive, args.threshold, console)


if __name__ == "__main__":
    main()