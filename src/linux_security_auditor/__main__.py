
from linux_security_auditor import __version__
from linux_security_auditor.checks.ssh_audit import audit_ssh


def print_header():
    print("\n" + "=" * 48)
    print("          LINUX SECURITY AUDITOR")
    print(f"                  v{__version__}")
    print("=" * 48)


def print_main_menu():
    print_header()
    print("\nMAIN MENU\n")
    print("  1. SSH Security")
    print("  0. Exit")
    print("\n" + "-" * 48)


def print_ssh_menu():
    print_header()
    print("\nSSH SECURITY\n")
    print("  1. Scan Global SSH")
    print("  2. Scan Specific User / Connection")
    print("  0. Back to Main Menu")
    print("\n" + "-" * 48)


def print_ssh_report(result):
    print("\n" + "=" * 48)
    print("              SSH SECURITY REPORT")
    print("=" * 48)

    status = result.get("status", "UNKNOWN")
    print(f"\nOverall Status: {status}")

    if result.get("error"):
        print(f"\nError: {result['error']}")
        print("\n" + "=" * 48)
        return

    for finding in result.get("findings", []):
        print("\n" + "-" * 48)
        print(f"Setting : {finding['setting']}")
        print(f"Value   : {finding['value']}")
        print(f"Status  : {finding['status']}")
        print(f"Title   : {finding['title']}")
        print(f"Details : {finding['details']}")

    if result.get("limitations"):
        print("\nLimitations:")
        for limitation in result["limitations"]:
            print(f"  - {limitation}")

    print("\n" + "=" * 48)


def scan_global_ssh():
    print("\nStarting global SSH security scan...")
    print("This may require administrator privileges.\n")

    result = audit_ssh()
    print_ssh_report(result)


def scan_specific_connection():
    print("\nSSH CONNECTION AUDIT")
    print("-" * 48)
    print("Enter the connection details.")
    print("Required fields cannot be empty.\n")

    user = input("Username: ").strip()
    host = input("Client hostname: ").strip()
    addr = input("Client IP address: ").strip()

    if not user or not host or not addr:
        print("\nError: Username, hostname and IP address are required.")
        return

    laddr = input("Server IP address [optional]: ").strip()
    lport = input("Server SSH port [optional, default 22]: ").strip()

    context = {
        "user": user,
        "host": host,
        "addr": addr,
    }

    if laddr:
        context["laddr"] = laddr

    if lport:
        context["lport"] = lport

    print("\nStarting connection-specific SSH scan...")
    print("This may require administrator privileges.\n")

    result = audit_ssh(context=context)
    print_ssh_report(result)


def ssh_menu():
    while True:
        print_ssh_menu()
        choice = input("Select an option [0-2]: ").strip()

        if choice == "1":
            scan_global_ssh()
            input("\nPress Enter to return to SSH menu...")

        elif choice == "2":
            scan_specific_connection()
            input("\nPress Enter to return to SSH menu...")

        elif choice == "0":
            break

        else:
            print("\nInvalid option. Please select 0, 1 or 2.")
            input("Press Enter to continue...")


def main():
    try:
        while True:
            print_main_menu()
            choice = input("Select an option [0-1]: ").strip()

            if choice == "1":
                ssh_menu()

            elif choice == "0":
                print("\nExiting Linux Security Auditor. Goodbye!")
                break

            else:
                print("\nInvalid option. Please select 0 or 1.")
                input("Press Enter to continue...")

    except KeyboardInterrupt:
        print("\n\nProgram interrupted. Exiting safely.")


if __name__ == "__main__":
    main()

