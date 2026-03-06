#---sql----
user = input()
query = "SELECT * FROM accounts WHERE user='" + user + "'"
execute(query)

username = input()
execute(username)

a = input()
b = a
c = b
execute(c)

#---xss----
name = input()
print(name)

msg = input()
display = msg
print(display)

#----sql and xsss ----
user = input()
query = "SELECT * FROM users WHERE name='" + user + "'"
execute(query)
print(user)