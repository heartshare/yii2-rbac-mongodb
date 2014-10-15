#安装方法
在项目的`composer.json`文件的`require`里面加入下列代码

```json
"require": {
        "iit/yii2-rbac-mongodb": "*",
    },
```

#使用方法

在项目的配置文件里面配置`authManager`处改成下列实例代码

```php
'components' => [
    'authManager'=>[
        'class'=>'yii/rbac/MongodbManager'
    ],
    ...
]
```

上述代码默认是调用`mongodb`组件链接mongodb数据库，请预先配置好mongodb数据源，如果需要自定义数据源可以加入`db`属性并指向你需要的数据源

```php
'components' => [
    'authManager'=>[
        'class'=>'yii/rbac/MongodbManager'
        'db'=>'Your Db Scoure'
    ],
    ...
]
```
