from src import tcp


server = tcp.ProxyTCPserver()

# работает на одном сайте, надо теперь решить 
# проблему с пересылкой данных и c dns, https

# для этого надо взять какойто socks4 прокси 
# уже написанный на пайтон, и протестировать его

# да нам срать на шифрование https, мы же работаем на уровне ниже
# по https мы никогда не найдём сервер
# предположение: dons сервер не рарешает

server.run()
