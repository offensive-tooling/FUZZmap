from fuzzmap.core.cli.cli import CLI

def main():
    cli = CLI()
    cli.print_banner()
    cli.print_usage()
    cli.run()

if __name__ == "__main__":
    main() 