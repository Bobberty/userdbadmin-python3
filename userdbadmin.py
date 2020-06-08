#!/usr/bin/python3

# This simple application provides a quick admin interface for using 
# BerkeleyDB as a user authentication source.  The Usernames and Passwords 
# are compatable with the UserDB Pam module.
# This is not intended to be a library.  Just a simple admin tool to help me
# move forward on testing authentication systems. 
# 
# All libraries except the bsddb3 library are standard python3.
#
# This script consists of 5 seperate commands:
#	create - Create a username/password entry.
#	changepassword - Modify the password for a specific user
#	verifypw - Verify the password used for a specific user
#	deluser - Remove a user from the database
#	list - List all users in the Database
#
# If the command is successful it will sysexit() with a zero(0), else it will 
# exit with a one(1).  Using a '-v' on the command line will allow the script to
# return a result to the command line.
#
# If the database file/path does not exist, the system will attempt to create
# a database.
#
# The script can only manage a single command per execution. And only a single
# user per command.
#
#
#
#
#	create
#		The create command will create a username/password in the 
#	specified database.  The password will be hashed using crypt(3).  If the
#	password and/or username is not on the command line, it will be prompted.
#	If a user already exists, the system will exit with an error.
#
#	ex:
#	cooluser@home:~/$ userdbadmin -v database.db create UserName PassworD
#	Created User
#	cooluser@home:~/$
#
#	
#	changepassword
#		The changepassword command will modify the password for a user
#	in the specified database.  Just like the Create command, the password
#	is hashed using crypt(3). If the password and/or username is not in the
#	command line, it will be prompted.
#
#	ex:
#	cooluser@home:~/$ userdbadmin -v database.db changepassword UserName PassworD
#	Changed Password
#	cooluser@home:~/$
#
#
#	verifypw
#		The verifypw command will take a username and password and 
#	attempt to verify with the specified database. This command will
#	sysexit() with a one (1) if the password is bad. If the password and/or 
#	username is not in the command line, it will be prompted. Using the '-v'
#	option will show the password check results.
#
#	ex:
#	cooluser@home:~/$ userdbadmin -v database.db verifypw UserName PassworD
#	Password Check Good
#	cooluser@home:~/$
#
#	
#	deluser
#		The deluser command will permanently remove a user from the 
#	specified database.  If the user doesn't exist in the database,
#	the system will sysexit() with a one (1).  If the username is not in 
#	the command line, it will be prompted.
#
#	ex:
#	cooluser@home:~/$ userdbadmin -v database.db deluser UserName PassworD
#	User Removed
#	cooluser@home:~/$
#
#
#	list
#		The list command will list all user entries in the specified
#	database as a simple string list seperated by a '/n'. This command
#	has an option to output in a python list by using '-p'.
#	
#	ex:
#	cooluser@home:~/$ userdbadmin database.db list
#	User1
#	User2
#	Bob
#	Mary
#	Hank
#	cooluser@home:~/$

import crypt, getpass, argparse, sys
from bsddb3 import db
from hmac import compare_digest as compare_hash



def GetUsername(UserName):
	if UserName:
		return UserName
	return input('Username: ')

def GetPassword (CoolPassword):
	if CoolPassword:
		return CoolPassword
	return getpass.getpass('Password: ')

def CreateUser( DBName, USERName = False, CLEARPassword = False):
	NewUserName = GetUsername(USERName)
	if not CheckUser(DBName, NewUserName)[0]:
		return 1, "User Already Exists"
	SetUserPassword(DBName, NewUserName, CLEARPassword)
	return 0, "Created User"

def ChangePassword(DBName, USERName = False, CLEARPassword = False):
	NewUserName = GetUsername(USERName)
	if CheckUser(DBName, NewUserName)[0]:
		return 1, "Bad Username"
	SetUserPassword(DBName, NewUserName, CLEARPassword)
	return 0,"Changed Password"

def DelUser(DBName, USERName = False):
	NewUserName = GetUsername(USERName)
	if CheckUser(DBName, NewUserName)[0]:
		return 1, "No User Found"
	DBName.delete(NewUserName.encode())
	return 0,"User Removed"

def CheckUserPassword (DBName, USERName = False, CLEARPassword = False):
	NewUserName = GetUsername(USERName)
	if CheckUser(DBName, NewUserName)[0]:
		return 1, "Bad Username"
	NewClearPW = GetPassword(CLEARPassword)
	CurrentPW = DBName.get(NewUserName.encode())
	HashedClearPW = crypt.crypt(NewClearPW, CurrentPW.decode())
	if compare_hash(HashedClearPW.encode(), CurrentPW):
		return 0, "Password Check Good"
	return 1, "Bad Password"

def SetUserPassword(DBName, USERName, CLEARPassword = False):
	NewClearPW = GetPassword(CLEARPassword)
	EncryptedPW = crypt.crypt(NewClearPW)
	DBName.put(USERName.encode(), EncryptedPW)
	return 0, "Successfully modified Password"

def CheckUser (DBName, USERName = False):
	NewUserName = GetUsername(USERName)
	try:
		CurrentPW = DBName.get(NewUserName.encode())
	except:
		return 1, "Bad Username"
	if not CurrentPW:
		return 1, "Bad Password"
	return 0, "Good Username"

def ListUsers (DBName, PythonList):
	userList = []
	for key in DBName.keys():
		userList.append(key.decode())
	if PythonList:
		newuserlist = userList
	else:	
		newuserlist = '\n'.join(userList)
	return [0,newuserlist]

parentparser = argparse.ArgumentParser(add_help = False)
parentparser.add_argument(action="store", dest = 'Username', help = 'Username required for the command', nargs = '?', default = False)
parentparser.add_argument(action="store", dest = 'ClearPassword', help = 'Clear password on the Command Line', nargs = '?', default = False)

parser = argparse.ArgumentParser(description = 'UserDB file Administration')
parser.add_argument(action="store", dest = "DBFilename", help = 'User DB path/filename')
parser.add_argument('-v', action='store_true', dest = 'verbose', default = False, help = 'Verbose response') 
subparsers = parser.add_subparsers( dest='command')

create_parser = subparsers.add_parser('create', help='Add a user to the User DB', parents = [parentparser])
verifypw_parser = subparsers.add_parser('verifypw', help = 'Verify Username/Password', parents = [parentparser])
changepassword_parser = subparsers.add_parser('changepassword', help='Change a user password', parents = [parentparser])

list_parser = subparsers.add_parser('list', help='List users in the User DB')
list_parser.add_argument('-p',action='store_true', dest='pythonlist', default = False, help = 'Python list')


deluser_parser = subparsers.add_parser('deluser', help = 'Delete a user from the Database')
deluser_parser.add_argument(action="store", dest = 'Username', help = 'Username to be deleted', nargs = '?', default = False)

args = parser.parse_args()

Result = [1,'No Command Issued']

UserDB = db.DB()
try:
	UserDB.open(args.DBFilename, db.DB_HASH, db.DB_CREATE)
except:
	sys.exit("Problem creating or accessing the DB")
	
if args.command == 'create':
	Result = CreateUser(UserDB,args.Username,args.ClearPassword)
elif args.command == 'deluser':
	Result = DelUser(UserDB, args.Username)
elif args.command == 'list':
	Result = ListUsers(UserDB, args.pythonlist)
	print(Result[1])
elif args.command == 'changepassword':
	Result = ChangePassword(UserDB, args.Username, args.ClearPassword)
elif args.command == 'verifypw':
	Result = CheckUserPassword(UserDB, args.Username, args.ClearPassword)

if args.verbose and (args.command != 'list'):
	print(Result[1])

sys.exit(Result[0])



