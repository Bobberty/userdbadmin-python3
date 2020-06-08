# userdbadmin-python3
A quick and simple script for administrating a bdb user db from the command line using python3.

 This simple application provides a quick admin interface for using 
 BerkeleyDB as a user authentication source.  The Usernames and Passwords 
 are compatable with the UserDB Pam module.
 This is not intended to be a library.  Just a simple admin tool to help me
 move forward on testing authentication systems. 
 
 All libraries except the bsddb3 library are standard python3.

 This script consists of 5 seperate commands:
	create - Create a username/password entry.
	changepassword - Modify the password for a specific user
	verifypw - Verify the password used for a specific user
	deluser - Remove a user from the database
	list - List all users in the Database

 If the command is successful it will sysexit() with a zero(0), else it will 
 exit with a one(1).  Using a '-v' on the command line will allow the script to
 return a result to the command line.

 If the database file/path does not exist, the system will attempt to create
 a database.

 The script can only manage a single command per execution. And only a single
 user per command.



	create
		The create command will create a username/password in the 
	specified database.  The password will be hashed using crypt(3).  If the
	password and/or username is not on the command line, it will be prompted.
	If a user already exists, the system will exit with an error.

	ex:
	cooluser@home:~/$ userdbadmin -v database.db create UserName PassworD
	Created User
	cooluser@home:~/$

	
	changepassword
		The changepassword command will modify the password for a user
	in the specified database.  Just like the Create command, the password
	is hashed using crypt(3). If the password and/or username is not in the
	command line, it will be prompted.

	ex:
	cooluser@home:~/$ userdbadmin -v database.db changepassword UserName PassworD
	Changed Password
	cooluser@home:~/$


	verifypw
		The verifypw command will take a username and password and 
	attempt to verify with the specified database. This command will
	sysexit() with a one (1) if the password is bad. If the password and/or 
	username is not in the command line, it will be prompted. Using the '-v'
	option will show the password check results.

	ex:
	cooluser@home:~/$ userdbadmin -v database.db verifypw UserName PassworD
	Password Check Good
	cooluser@home:~/$

	
	deluser
		The deluser command will permanently remove a user from the 
	specified database.  If the user doesn't exist in the database,
	the system will sysexit() with a one (1).  If the username is not in 
	the command line, it will be prompted.

	ex:
	cooluser@home:~/$ userdbadmin -v database.db deluser UserName PassworD
	User Removed
	cooluser@home:~/$


	list
		The list command will list all user entries in the specified
	database as a simple string list seperated by a '/n'. This command
	has an option to output in a python list by using '-p'.
	
	ex:
	cooluser@home:~/$ userdbadmin database.db list
	User1
	User2
	Bob
	Mary
	Hank
	cooluser@home:~/$
