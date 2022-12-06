import sys
import MySQLdb


def execute(conn, sql):
    select = True
    if not sql.startswith('SELECT') and not sql.startswith('SHOW'):
        select = False

    curs = conn.cursor(MySQLdb.cursors.SSDictCursor)
    curs.execute(sql)
    if select:
        rows = curs.fetchall()
        curs.close()
        return select, rows

    ret = conn.affected_rows()
    curs.close()
    return select, ret

if __name__ == '__main__':
  assert len(sys.argv) == 6
  user = sys.argv[1]
  passwd = sys.argv[2]
  db = sys.argv[3]
  host = sys.argv[4]
  port = sys.argv[5]

  conn = MySQLdb.connect(host=host, port=int(port), user=user, passwd=passwd, db=db)
  conn.autocommit(False)
  for line in sys.stdin:
    print line.rstrip()
    (select, rows) = execute(conn,line.rstrip())
    if select:
      for row in rows:
        print row
