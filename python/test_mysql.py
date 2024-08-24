#----------------------------------------------------------------------------------------------
# https://dev.mysql.com/doc/connector-python/en/connector-python-example-cursor-select.html
#---------------------------------------------------------------------------------------------
def build_delta(cnx):
    cursor=cnx.cursor()
    cursor.execute("delete from delta")
    query = ("insert into delta "
            "select yesterday.account, yesterday.amount, yesterday.currency "
            "from yesterday left join today "
            "on yesterday.account = today.account "
            "where today.account is null"
          )
    cursor.execute(query)
    cnx.commit()
#-------------------------------------------------------------------------
# here we go
#-------------------------------------------------------------------------
import mysql.connector
cnx = mysql.connector.connect(user='root', password='password',
                              host='127.0.0.1',
                              database='test_db')
build_delta(cnx)
cursor = cnx.cursor()

query = ("SELECT account, amount, currency FROM delta")

cursor.execute(query)
print("listing the delta")
for (account, amount, currency) in cursor:
  print("account:" + account + " amount:", str(amount) + " cur:" + currency)
  
cursor.close()
cnx.close()