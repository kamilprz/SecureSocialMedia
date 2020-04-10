from pymongo import MongoClient
from getpass import getpass
from tmp import temp

mongoC = temp.getMongoClient
client = MongoClient(mongoC)
db = client.get_database('telecomms_db')
users = db.users
groups = db.groups

# print(users.count_documents({}))

# collection.insert_one/many

while True:
    action = input('What would you like to do >>>  ')
    if action == 'register':
        print('Alo, please register for the forum.')
        username = input('Username: ')
        # password = input('Password: ')
        password = getpass()
        new_user = {
            'username' : username,
            'password' : password
        }
        users.insert_one(new_user)

    elif action == 'logout' or action == 'stop':
        print('byebye')
        break

    else:
        print('xddd')