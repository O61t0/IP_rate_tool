from log_package.logger import Logger



class demo(object):
    def __init__(self):
        self.log=Logger('scrapy').get_logger()


def Log(func):
    def wrapper(*args, **kwargs):
        try :
            func(*args, **kwargs)
        except Exception as e:
            demo().log.error(e)
    return wrapper



