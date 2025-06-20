#!/usr/bin/env python3

import subprocess
import os
import sys
from simple_term_menu import TerminalMenu

def display_options(options, title):
    terminal_menu = TerminalMenu(
        options,
        title=title,
        menu_cursor="> ",
        menu_cursor_style=("fg_yellow", "bold"),
        menu_highlight_style=("fg_yellow", "bold"),
        cycle_cursor=True,
        clear_screen=False
    )
    menu_entry_index = terminal_menu.show()
    if menu_entry_index is None:
        raise KeyboardInterrupt
    return menu_entry_index

def check_files_presence(files):
    missing_files = [file for file in files if not os.path.isfile(file)]
    return missing_files

def run_command(command):
    try:
        subprocess.run(command, check=True, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while trying to run {command}: {e}")
    except FileNotFoundError:
        print(f"Command not found: {command}")
    except PermissionError:
        print(f"Permission denied: Unable to run {command}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def main():
    if os.geteuid() != 0:
        print("This script must be run as root.")
        sys.exit(1)

    files = ['./discovery', './scanner', './ssid']

    while True:
        try:
            missing_files = check_files_presence(files)

            if missing_files:
                print("\033[91mSome files are missing, running setup.sh to install dependencies? (y/n)\033[0m")
                choice = input().strip().lower()
                if choice == 'y':
                    if os.path.isfile('./setup.sh'):
                        run_command("chmod +x ./setup.sh")
                        run_command("./setup.sh")
                    else:
                        print("setup.sh not found.")
                        continue
                elif choice == 'n':
                    print("Setup skipped. Exiting.")
                    break
                else:
                    print("Invalid choice. Please enter 'y' or 'n'.")
                    continue

            categories = ["Network", "Wifi"]
            try:
                category_index = display_options(categories, "Please select a category:")
            except KeyboardInterrupt:
                print("\nProcess interrupted. Exiting.")
                break

            if category_index == 0:
                network_options = [
                    "Discovery (local network info, port switch, VLANs issues)",
                    "Scanner (nmap scan after an initial Discovery analysis)",
                    "Sniffer (analyze vulnerabilities by listening to network packets)",
                    "MITM (printer traffic interception and analysis)",
                    "Egress (outbound port filtering analysis)"
                ]
                try:
                    network_choice = display_options(network_options, "Please select a program to run:")
                except KeyboardInterrupt:
                    print("\nProcess interrupted. Returning to main menu.")
                    continue

                commands = {
                    0: './discovery',
                    1: './scanner',
                    2: 'python3 above.py --timer 240',
                    3: 'python3 mitm.py',
                    4: 'python3 egress.py'
                }
                try:
                    run_command(commands[network_choice])
                except KeyboardInterrupt:
                    print("\nProcess interrupted. Returning to menu.")
                    continue

            elif category_index == 1:
                wifi_options = [
                    "SSID (Detects and classifies nearby SSIDs)"
                ]
                try:
                    wifi_choice = display_options(wifi_options, "Please select a program to run:")
                except KeyboardInterrupt:
                    print("\nProcess interrupted. Returning to main menu.")
                    continue

                commands = {
                    0: './ssid'
                }
                try:
                    run_command(commands[wifi_choice])
                except KeyboardInterrupt:
                    print("\nProcess interrupted. Returning to menu.")
                    continue

        except KeyboardInterrupt:
            print("\nProcess interrupted. Exiting.")
            break

if __name__ == "__main__":
    main()
