from pymongo import MongoClient
from getpass import getpass
from tmp import temp

mongoC = temp.getMongoClient()
client = MongoClient(mongoC)
db = client.get_database('telecomms_db')
users = db.users
groups = db.groups


def main():
    try:
        loginUser = ''
        # print some sort of 'help' with commands available
        while True:
            action = input('\nWhat would you like to do >>>  ')
            if action == 'register':
                register()

            elif action == 'login':
                login()

            elif action == 'logout' or action == 'stop':
                logout()
                break

            else:
                print('Invalid input. Type \'help\' for more info.')
    except (KeyboardInterrupt, SystemExit):
        print('\n\nShutting down...')    


def register():
    print('Please enter a username and password.')
    username = input('Username: ')
    # password = input('Password: ')
    password = getpass()
    new_user = {
        'username' : username,
        'password' : password
    }
    users.insert_one(new_user)


def login():
    username = input('Username: ')
    user = users.find_one({'username': username})
    if user:
        password = getpass()
        if password == user['password']:
            loginUser = username
            print('Logged in as {0}'.format(username))
        else:
            print('Wrong password')
    else:
        print('User not found')


def logout():
    loginUser = ''
    print('Logged out.')


if __name__ == '__main__':
    main()

