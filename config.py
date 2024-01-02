USERNAME = 'root'
PASSWORD = '1234'
HOST = '127.0.0.1'
PORT = '3306'
DATABASE = 'test'

DB_URL = 'mysql+pymysql://{}:{}@{}:{}/{}?charset=utf8'.format(USERNAME, PASSWORD, HOST, PORT, DATABASE)

SQLALCHEMY_DATABASE_URI = DB_URL

# 动态追踪修改设置，如未设置只会提示警告
SQLALCHEMY_TRACK_MODIFICATIONS = False

# 查询时会显示原始sql语句
SQLALCHEMY_ECHO = True
SECRET_KEY = 'Thisissupposedtobesecret!'


# 邮箱配置
MAIL_SERVER = "smtp.qq.com"
MAIL_USE_TLS = True
MAIL_PORT = 587
# 你个人的邮箱
MAIL_USERNAME = "3336545349@qq.com"

# 刚刚获取到的授权码填在这里
MAIL_PASSWORD = "iofxvogxxjjecheg"
# 你的邮箱名字可以和MAIL_USERNAME一样
MAIL_DEFAULT_SENDER = "3336545349@qq.com"
