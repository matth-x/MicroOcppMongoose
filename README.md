# AOcppMongoose
Mongoose WebSocket adapter for ArduinoOcpp

## Dependencies

The following projects must be available on the include path:

- [Mongoose Embedded Networking Library v7.8](https://github.com/cesanta/mongoose/tree/76e6b23a4f0261dd534d33632f42ea1bba99dc85): This project works with the amalgamated files `mongoose.h` and `mongoose.c`. You may need to copy them from the Mongoose-repository into the `src` folder of your project.
- [ArduinoJson v6.19.1](https://github.com/bblanchon/ArduinoJson/tree/079ccadbee4100ad0b2d06f11de8c412b95853c1)
- [ArduinoOcpp](https://github.com/matth-x/ArduinoOcpp)

The setup is done if the following include statements work:

```cpp
#include "mongoose.h"
#include <ArduinoJson.h>
#include <ArduinoOcpp.h>
```

The last dependency is [base64-converter by Densaugeo](https://github.com/Densaugeo/base64_arduino), but it is already included in this repository. Thanks to [Densaugeo](https://github.com/Densaugeo) for providing it!

## License

This project is licensed under the GPL as it uses the [Mongoose Embedded Networking Library](https://github.com/cesanta/mongoose). If you have a proprietary license of Mongoose, then the [MIT License](https://github.com/matth-x/ArduinoOcpp/blob/master/LICENSE) applies.
