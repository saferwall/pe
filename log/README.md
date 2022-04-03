# Logger

This code was taken from the go microservice framework [kratos](https://github.com/go-kratos/kratos).

## Usage

### Structured logging

```go
logger := log.NewStdLogger(os.Stdout)
// fields & valuer
logger = log.With(logger,
    "service.name", "hellworld",
    "service.version", "v1.0.0",
    "ts", log.DefaultTimestamp,
    "caller", log.DefaultCaller,
)
logger.Log(log.LevelInfo, "key", "value")

// helper
helper := log.NewHelper(logger)
helper.Log(log.LevelInfo, "key", "value")
helper.Info("info message")
helper.Infof("info %s", "message")
helper.Infow("key", "value")

// filter
log := log.NewHelper(log.NewFilter(logger,
	log.FilterLevel(log.LevelInfo),
	log.FilterKey("foo"),
	log.FilterValue("bar"),
	log.FilterFunc(customFilter),
))
log.Debug("debug log")
log.Info("info log")
log.Warn("warn log")
log.Error("warn log")
```

## Third party log library

If you need to implement a third party logging library like `zap`, have a look this [url](https://github.com/go-kratos/kratos/tree/main/contrib/log).