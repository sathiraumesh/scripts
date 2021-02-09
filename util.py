import datetime
import sys



def get_date_tommorow() :
  return  str(datetime.date.today() + datetime.timedelta(days=1))
