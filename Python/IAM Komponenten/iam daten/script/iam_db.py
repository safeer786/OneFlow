'''
Created on 05.06.2018

@author: feuk8fs
'''


def main():
    import argparse
    from iam_db_func import create_db

    parser = argparse.ArgumentParser(description = 'Usage Exporter')
    commands = parser.add_subparsers(title = 'subcommands', dest = 'command')

    create_db_paraser = commands.add_parser(name = "create-db")
    create_db_paraser.add_argument("-a", '--accounts', type = str , help = "The accounts that you want to get information from.for example {'966497653753':'ADFS-PlatformOperator', ....}", required = True)
    create_db_paraser.set_defaults(func = create_db)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__": main()
