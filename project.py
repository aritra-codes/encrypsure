from re import findall, fullmatch
import csv
from argparse import ArgumentParser
from tabulate import tabulate
from sys import exit
from random import choice, shuffle
from string import ascii_letters, ascii_uppercase, digits, punctuation

def main():
    p = ArgumentParser(
        description="View or store passwords in a database")
    p.add_argument("service", nargs="?")
    p.add_argument("username", nargs="?")
    p.add_argument("-c", "--create", action="store_true", help="create a new entry")
    p.add_argument("-e", "--edit", action="store_true", help="edit the password of an existing entry")
    p.add_argument("-d", "--delete", action="store_true", help="delete an existing entry")
    p.add_argument("-ap", "--autopass", action="store_true", help="auto generate a 16 character long password")
    p.add_argument("-a", "--all", action="store_true", help="show all entries")
    args = p.parse_args()
    args_service = args.service
    args_username = args.username
    args_edit = args.edit

    def get_valid_input(input_name, current_value="", valid_values=None, valid_input_name="", invalid_values=None, invalid_input_name="", case_sensitive=True, is_service=False):
        def print_invalid_input_message(name):
            print(f"Please input a/an {name}.")

        input_value = current_value
        skip = False

        if input_value:
            skip = True

        while True:
            if skip:
                skip = False
            else:
                input_value = input(f"{input_name.capitalize()}: ")

                if not input_value:
                    print_invalid_input_message(input_name)
                    continue

            if not case_sensitive:
                input_value = input_value.lower()
            if is_service:
                input_value = deduce_service(input_value)

            if valid_values and input_value not in valid_values:
                print_invalid_input_message(valid_input_name if valid_input_name else f"valid {input_name}")
                continue

            if invalid_values and input_value in invalid_values:
                print_invalid_input_message(invalid_input_name if invalid_input_name else f"valid {input_name}")
                continue

            break

        return input_value

    fixed_punctuation = [
        char for char in punctuation if char not in ["'", '"', "\\"]]

    def get_valid_encrypted_password(input_name, disable_autopass=False):
        if not disable_autopass and args.autopass:
            letters_list = list(ascii_letters)
            digits_list = list(digits)
            password = [choice(letters_list).upper(), choice(digits_list), choice(fixed_punctuation)]
            for _ in range(13):
                password += choice(letters_list + digits_list + fixed_punctuation)
            shuffle(password)
            password = encrypt("".join(password))
        else:
            while True:
                try:
                    password = encrypt(get_valid_input(input_name))
                    break
                except KeyError:
                    print("Invalid character(s) in password, please try again.")

        return password

    MASTER_PASSWORD_FILE_NAME = "master_password.txt"

    try:
        with open(MASTER_PASSWORD_FILE_NAME) as file:
            master_password = encrypt(file.readlines()[0], True)
    except IndexError:
        pass
    except FileNotFoundError:
        while True:
            match input("Currently, there is no master password. Would to like to make one (y/n)? ").lower():
                    case "y" | "yes":
                        with open(MASTER_PASSWORD_FILE_NAME, "w") as file:
                            file.write(get_valid_encrypted_password("master password", True))

                        exit("Please reopen the program.")
                    case "n" | "no":
                        open(MASTER_PASSWORD_FILE_NAME, "w")
                        break
                    case _:
                        print("Invalid response, try again.")
    else:
        while master_password != input("Master password: "):
            print("Incorrect master password.")

    PASSWORDS_FILE_NAME = "passwords.csv"
    SERVICE_KEY, USERNAME_KEY, PASSWORD_KEY = "service", "username", "password"
    PASSWORDS_FILE_FIELDNAMES = [SERVICE_KEY, USERNAME_KEY, PASSWORD_KEY]

    try:
        open(PASSWORDS_FILE_NAME)
    except FileNotFoundError:
        with open(PASSWORDS_FILE_NAME, "w") as file:
            writer = csv.writer(file)

            writer.writerow(PASSWORDS_FILE_FIELDNAMES)

    if args.create:
        with open(PASSWORDS_FILE_NAME) as file:
            reader = csv.DictReader(file)

            service = get_valid_input("service", args_service, case_sensitive=False, is_service=True)

            existing_usernames = []
            for row in reader:
                if row[SERVICE_KEY] == service:
                    existing_usernames.append(row[USERNAME_KEY])
            username = get_valid_input("username", args_username, invalid_values=existing_usernames, invalid_input_name="username that isn't already associated with an entry of that service")

        with open(PASSWORDS_FILE_NAME, "a") as file:
            writer = csv.DictWriter(file, fieldnames=PASSWORDS_FILE_FIELDNAMES)

            writer.writerow({SERVICE_KEY: service, USERNAME_KEY: username, PASSWORD_KEY: get_valid_encrypted_password("password")})

        print("Successfully created new entry!")

    elif args_edit or args.delete:
        with open(PASSWORDS_FILE_NAME) as file:
            reader = csv.DictReader(file)

            valid_services = set()
            for row in reader:
                valid_services.add(row[SERVICE_KEY])
            service = get_valid_input("service", args_service, valid_services, "existing entry's service", case_sensitive=False, is_service=True)

            file.seek(1)

            valid_usernames = set()
            for row in reader:
                if row[SERVICE_KEY] == service:
                    valid_usernames.add(row[USERNAME_KEY])
            username = get_valid_input("username", args_username, valid_usernames, "existing entry's username of that service")

            if args_edit:
                new_password = get_valid_encrypted_password("new password")

            file.seek(0)

            while True:
                match input(f"Are you sure you want to {'edit' if args_edit else 'delete'} this entry (y/n)? ").lower():
                    case "y" | "yes":
                        data = []

                        for row in reader:
                            if row[SERVICE_KEY] == service and row[USERNAME_KEY] == username:
                                if args_edit:
                                    edited_row = row
                                    edited_row[PASSWORD_KEY] = new_password

                                    data.append(list(edited_row.values()))
                            else:
                                data.append(list(row.values()))

                        break
                    case "n" | "no":
                        exit(f"Exiting program without {'edit' if args_edit else 'delet'}ing entry...")
                    case _:
                        print("Invalid response, try again.")

                print("Please input a valid confirmation (y/n).")

        with open(PASSWORDS_FILE_NAME, "w") as file:
            writer = csv.writer(file)

            for row in data:
                writer.writerow(row)

        print(f"Successfully {'edit' if args_edit else 'delet'}ed entry.")

    else:
        if args.all:
            service, username = "", ""
        else:
            service = deduce_service(args_service if args_service else input("Service (press enter if you want all services): ")).lower()
            username = args_username if args_username else input("Username (press enter if you want all usernames): ")
        entry_table = []

        with open(PASSWORDS_FILE_NAME) as file:
            reader = csv.DictReader(file)

            for row in reader:
                if (service and row[SERVICE_KEY] != service) or (username and row[USERNAME_KEY] != username):
                    continue

                password = encrypt(row["password"], True)

                entry_table.append([row[SERVICE_KEY], row[USERNAME_KEY], password, check_password_strength(password, {
                1: "Bad",
                2: "Good",
                3: "Excellent"
            })])

        if entry_table:
            entry_table.sort(key=lambda x: (x[1], x[2]))

            print(tabulate([PASSWORDS_FILE_FIELDNAMES + ["strength"]] + entry_table, headers="firstrow", tablefmt="simple_outline"))
        else:
            print("No entries found.")


def deduce_service(s):
    return fullmatch(r"(?:https?://)?(?:.+?\.)?(.*?)(?:\..+?/?.*)?", s).group(1)


def check_password_strength(s, password_strength_values={}):
    has_uppercase = any([char in ascii_uppercase for char in s])
    has_digits = any([char in digits for char in s])
    has_punctuation = any([char in punctuation for char in s])

    strength = 1

    if has_uppercase and has_digits:
        strength += 1

        if has_punctuation and len(s) >= 16:
            strength += 1

    try:
        return password_strength_values[strength]
    except KeyError:
        return strength


def encrypt(s, reverse=False):
    encrypt_translation = {
        "a":"x)2",
        "b":"%B6",
        "c":"a8$",
        "d":"F1|",
        "e":"_7B",
        "f":"*j3",
        "g":"4:T",
        "h":"k_2",
        "i":"7P%",
        "j":"9<l",
        "k":"r8:",
        "l":"1W:",
        "m":"s8;",
        "n":"S9&",
        "o":"f6@",
        "p":"2+s",
        "q":"C6`",
        "r":"3?k",
        "s":"3L~",
        "t":"=n7",
        "u":")7b",
        "v":"4d?",
        "w":"<M8",
        "x":"[g4",
        "y":"u1#",
        "z":"?0k",
        "A":"4,R",
        "B":".4H",
        "C":"7<b",
        "D":"o^8",
        "E":"-t6",
        "F":"f5,",
        "G":"6(P",
        "H":";W5",
        "I":"=U6",
        "J":"4$r",
        "K":"V5^",
        "L":"s:7",
        "M":"O0_",
        "N":"`5m",
        "O":"?2K",
        "P":"/G7",
        "Q":"O&9",
        "R":"U1}",
        "S":"9&H",
        "T":"7&W",
        "U":"q4^",
        "V":"3*W",
        "W":"q4[",
        "X":"8I(",
        "Y":"*S0",
        "Z":"n8.",
        "0":"&6x",
        "1":"4E:",
        "2":"f7&",
        "3":"B6_",
        "4":"6a*",
        "5":"_0U",
        "6":"p8-",
        "7":"L=5",
        "8":"q~9",
        "9":")P1",
        "!":"1|S",
        "#":"r9}",
        "$":"2U(",
        "%":"9F#",
        "&":"}4M",
        "(":"/0W",
        ")":"i(8",
        "*":";8O",
        "+":"1a(",
        ",":"3<I",
        "-":"T;4",
        ".":"[H9",
        "/":"Q5&",
        ":":"P|1",
        ";":"L4%",
        "<":"m3.",
        "=":"f3*",
        ">":"5C.",
        "?":"]i7",
        "@":"2b(",
        "[":"6.I",
        "]":"a5_",
        "^":"7R)",
        "_":"%V7",
        "`":"b8$",
        "{":"<0v",
        "|":"#o5",
        "}":"S`6",
        "~":"H5^"
    }

    translation = {v: k for k, v in encrypt_translation.items()} if reverse else encrypt_translation

    if reverse:
        if len(s) % 3 != 0:
            raise KeyError

        password = findall(".{3}", s)
    else:
        password = s

    output = ""

    for char in password:
        output += translation[char]

    return output

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        exit("\nExiting program...")