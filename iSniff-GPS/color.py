# stolen from https://github.com/securusglobal/abrupt by @tweksteen

style_normal = "\033[0m"
style_great_success = "\033[1;32m"
style_success = "\033[32m"
style_error = "\033[1;31m"
style_warning = "\033[1;33m"
style_info = "\033[1;34m"
style_stealthy = "\033[37m"
  
def success(s):
  return style_success + s + style_normal

def error(s):
  return style_error + s + style_normal

def warning(s):
  return style_warning + s + style_normal

def great_success(s):
  return style_great_success + s + style_normal

def info(s):
  return style_info + s + style_normal

def stealthy(s):
  return style_stealthy + s + style_normal

def color_status(status):
  if status.startswith("2"):
    return great_success(status)
  elif status.startswith("3"):
    return warning(status)
  elif status.startswith("4") or status.startswith("5"):
    return error(status)
  return stealthy(status)
    
