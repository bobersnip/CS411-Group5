To get the skeleton running, open a terminal and do the following:
	1. enter the skeleton folder 'cd path/to/skeleton'
	2. install all necessary packages 'pip install -r requirements.txt' (or use pip3)

Intermediate steps:
- Start your sql server by opening an administrator command prompt and using 'mysqld' and then 'net start MySQL80'
- (OPTIONALLY) Then use 'mysql -u <YOUR SQL USERNAME> -h 127.0.0.1 -p' and then type in your password


	3. open config.py using your favorite editor, change #PASSWORD in 'password = '#PASSWORD' to your MySQL root password

	4. back to the terminal, run the app 'python app.py' (or use python3)
	5. open your browser, and open the local website 'localhost:5000'