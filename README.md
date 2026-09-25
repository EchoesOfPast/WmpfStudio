# WmpfStudio

通用微信小程序调试台（Windows，C++ / Qt6）。指向微信里打开的任意小程序，即可在其 AppService 上下文里执行 JS、查看页面、导出 Storage。

## 功能

- 一键开启 WMPF 调试通道（Native 注入，自带 52 个微信版本的偏移表，防僵尸看门狗）
- 页面识别：按关键词（appId / URL 片段）或从下拉列表选取当前页面
- JS 控制台：在小程序上下文执行任意表达式（`wx.*`、业务函数均可直达），JSON 结果自动美化
- Storage 导出：一键把小程序全部本地存储 dump 成格式化 JSON
- 内存仪器：驻留在目标进程里的 hook DLL 提供通用原语（共享内存 IPC）——内存读写、模块/导出枚举、带通配的模式扫描、任意函数调用（PIDs），卡片式操作直达
- `--screenshot <png>` 离屏渲染自检；`--unpack-test` / `--fx-test` 无界面自检入口

## 使用

1. PC 微信登录，打开目标小程序
2. 运行 `WmpfStudio.exe` → 「启动通道」→「刷新页面」
3. 输入框写 JS 表达式，回车执行

## 从源码构建

依赖：CMake + Qt 6（win64_mingw）+ MinGW 13.x：

```bat
cmake -G "MinGW Makefiles" -DCMAKE_PREFIX_PATH=C:/Qt6/6.7.3/mingw_64 -S . -B build
cmake --build build --config Release -j8
cmake --build build --target deploy
```

## 发版

推 tag 即可（CI 自动构建并发布 zip）：

```bat
git tag v0.x.y && git push origin v0.x.y
```

## 目录结构

```
src/studio/            界面与控制台逻辑
src/wmpf/              调试通道（hook DLL、注入、偏移表、WARemoteDebug↔CDP 翻译）
res/wmpf-offsets/win32/   按微信版本的偏移表
```

## 免责

仅供学习与研究使用。
