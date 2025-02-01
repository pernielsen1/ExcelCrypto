#----------------------------------------------------------------------------------------------
# https://dev.mysql.com/doc/connector-python/en/connector-python-example-cursor-select.html
#---------------------------------------------------------------------------------------------
import mysql.connector

def drop_table(cnx, table_name):
    cursor=cnx.cursor()
    # drop the old tables if they exist
    try:
        cursor.execute("drop table test_db." + table_name)
    except mysql.connector.Error as err:
        print(err.msg)
    else:
        print("table:" + table_name + " dropped")

def create_table_and_fill(cnx):
    tbl_name = "selected_cnt"
    drop_table(cnx, tbl_name)


    tbl_name = "test_c_and_l"
    drop_table(cnx, tbl_name)

    cursor = cnx.cursor()
    fields =  "(id integer, c char(2), l char(2))"
    cursor.execute("create table " + tbl_name + " " + fields)
   
    cursor.execute( "INSERT INTO " + tbl_name + " (id, c, l)" +  " VALUES(" +  "1," + "'SE'," + "'SE')")
    cursor.execute( "INSERT INTO " + tbl_name + " (id, c, l)" +  " VALUES(" + "52," + "'SE'," + "'SE')")
    cursor.execute( "INSERT INTO " + tbl_name + " (id, c, l)" +  " VALUES(" +  "1," + "'SE'," + "'EN')")
    cursor.execute( "INSERT INTO " + tbl_name + " (id, c, l)" +  " VALUES(" + "51," + "'NO'," + "'EN')")

    cursor.execute( "INSERT INTO " + tbl_name + " (id, c, l)" +  " VALUES(" + "41," + "'AT'," + "'DE')")
    cursor.execute( "INSERT INTO " + tbl_name + " (id, c, l)" +  " VALUES(" + "41," + "'AT'," + "'EN')")
    cursor.execute( "INSERT INTO " + tbl_name + " (id, c, l)" +  " VALUES(" + "41," + "'DE'," + "'DE')")
    cursor.execute( "INSERT INTO " + tbl_name + " (id, c, l)" +  " VALUES(" + "41," + "'DE'," + "'EN')")

    cnx.commit()
    return


#--------------------------------------------------------------------------------------
# here we go
#---------------------------------------------------------------------------------------
cnx = mysql.connector.connect(user='root', password='password',
                              host='127.0.0.1',
                              database='test_db')

create_table_and_fill(cnx)

cursor = cnx.cursor()

print("Listing full table:")
query = "SELECT id, c, l from test_c_and_l"
cursor.execute(query)
for (id, c, l) in cursor:
  print("id:" + str(id) + " c:", c + " l:" + l)

print("Listing l per c")
query = "select distinct a.c, b.l from test_c_and_l a inner join test_c_and_l b on a.c=b.c"
cursor.execute(query)
for (c, l) in cursor:
  print(" c:" + c + " l:" + l)
 
cursor.close()
cnx.close()
