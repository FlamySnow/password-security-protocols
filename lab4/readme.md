# ПО восстановления пароля для протокола IKEv1

> Данное ПО представлено в двух модулях: первый модуль генерирует тесты, второй модуль подбирает пароль.
> ПО использует режим протокола *Aggressive Mode*.

## 1. Генератор тестов для протокола IKEv1
    
ПО принимает на вход пароль и название хеш-функции, которая будет использована для генерации хеша, а на выход файл с
названием *Password_HashFunctionName.txt*. В выходном файле - строка следующего формата: 
`Ni*Nr*g_x*g_y*Ci*Cr*SAi*IDi*HASH`

### Входные параметры:
1) `-m HashFunctionName` - параметр для выбора хеш-функции, где `HashFunctionName` может быть либо `md5`, либо `sha1`.
2) `-p Password` - пароль для вычисления хеша, строка в кодировке UTF-8.

Данные параметры являются обязательными.

### Примеры запуска:

`python gen.py -m sha1 -p 1aer23gd`
`python gen.py -m md5 -p ds09fs0w9`

## 2. Подбор пароля для протокола IKEv1

ПО принимает на вход маску для подбора пароля и файл, в котором находятся данные для вычисления хеша.
В конце работы ПО выводится сообщение о нахождении пароля или о том, что поиск не удался.

### Входные параметры:

1) `-m MASK` - маска для подбора пароля, может состоять из следующих символов: `a` - любые латинские буквы и арабские 
цифры, `s` - только маленькие латинские буквы, `l` - только большие латинские буквы, `d` - только арабские цифры. 
Количество символов в маске соответствует длине генерируемого пароля.
2) `input_file` - файл, в котором находится строка в выше приведённом формате.

Оба параметра являются обязательными.

### Примеры запуска:

`python crack.py -m aassldld test.txt`
`python crack.py -m lllll test.txt`
`python crack.py -m lllasd test.txt`