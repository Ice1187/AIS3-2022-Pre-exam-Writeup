使用的程式語言是「文言」。

壹：首先，安裝文言套件

```
$ npm install @wenyan/core
$ npm install js-beautify
```

貳：將文言轉成 Javascript

```
$ cd ./chal
$ npx --package=@wenyan/cli wenyan -c -o ../decomp.js -r --roman pinyin 殼.wy
$ node_modules/.bin/js-beautify ./decomp.js > decomp_beauty.js
```

參：分析程式碼

1. 指令開始需加上 `蛵煿 `
2. 正解為「密旗」(MI4QI2)變數

```
// Input command$
var KE2 = _ => {};$
KE2 = RU4 => {$
    const _ans92 = SHI3YU2(RU4)("蛵煿 ");$
    var DING1CHEN2 = _ans92;$
    if (DING1CHEN2) {$
        const _ans93 = ZI4ZI3(RU4)(3);$
        var DI4XIN1 = _ans93;$
        const _ans94 = XI1YI1(DI4XIN1);$
    } else {$
        if (RU4 == "助") {$
            const _ans95 = LING2LONG2();$
        } else {$
            const _ans96 = "指令「" + RU4;$
            var BING3DING1 = _ans96;$
            const _ans97 = BING3DING1 + "」不存在\n";$
            var XIN1WU3 = _ans97;$
            const _ans98 = SHU1CHU1(XIN1WU3);$
        };$
    };$
    const _ans99 = SHU1CHU1(NIE4);$
};$
```

肆：執行程式

```
$ ./node_modules/.bin/wenyan --dir ./chal/藏書樓/ ./chal/殼.wy
```

伍：暴力解了吧
