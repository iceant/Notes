# Spring Boot 模块化原理

## /META-INF/spring.factories 

spring-core包里定义了`SpringFactoriesLoader`类，这个类实现了检索META-INF/spring.factories文件，并获取指定接口的配置的功能。在这个类中定义了两个对外的方法：

**loadFactories** 根据接口类获取其实现类的实例，这个方法返回的是对象列表。
**loadFactoryNames** 根据接口获取其接口类的名称，这个方法返回的是类名的列表。
上面的两个方法的关键都是从指定的ClassLoader中获取`spring.factories`文件，并解析得到类名列表，具体代码如下

```java
public static List<String> loadFactoryNames(Class<?> factoryClass, ClassLoader classLoader) {
    String factoryClassName = factoryClass.getName();
    try {
        Enumeration<URL> urls = (classLoader != null ? classLoader.getResources(FACTORIES_RESOURCE_LOCATION) :
        ClassLoader.getSystemResources(FACTORIES_RESOURCE_LOCATION));
        List<String> result = new ArrayList<String>();
        while (urls.hasMoreElements()) {
            URL url = urls.nextElement();
            Properties properties = PropertiesLoaderUtils.loadProperties(new UrlResource(url));
            String factoryClassNames = properties.getProperty(factoryClassName);
            result.addAll(Arrays.asList(StringUtils.commaDelimitedListToStringArray(factoryClassNames)));
        }
        return result;
    }
    catch (IOException ex) {
        throw new IllegalArgumentException("Unable to load [" + factoryClass.getName() +
                "] factories from location [" + FACTORIES_RESOURCE_LOCATION + "]", ex);
    }
}
```

从代码中我们可以知道，在这个方法中会遍历整个ClassLoader中所有jar包下的spring.factories文件。也就是说我们可以在自己的jar中配置spring.factories文件，不会影响到其它地方的配置，也不会被别人的配置覆盖。

spring.factories的是通过Properties解析得到的，所以我们在写文件中的内容都是安装下面这种方式配置的：

com.xxx.interface=com.xxx.classname

如果一个接口希望配置多个实现类，可以使用’,’进行分割。

### spring-boot 下的 spring.factories 内容举例

```java
# Logging Systems
org.springframework.boot.logging.LoggingSystemFactory=\
org.springframework.boot.logging.logback.LogbackLoggingSystem.Factory,\
org.springframework.boot.logging.log4j2.Log4J2LoggingSystem.Factory,\
org.springframework.boot.logging.java.JavaLoggingSystem.Factory

# PropertySource Loaders
org.springframework.boot.env.PropertySourceLoader=\
org.springframework.boot.env.PropertiesPropertySourceLoader,\
org.springframework.boot.env.YamlPropertySourceLoader

# ConfigData Location Resolvers
org.springframework.boot.context.config.ConfigDataLocationResolver=\
org.springframework.boot.context.config.ConfigTreeConfigDataLocationResolver,\
org.springframework.boot.context.config.StandardConfigDataLocationResolver

# ConfigData Loaders
org.springframework.boot.context.config.ConfigDataLoader=\
org.springframework.boot.context.config.ConfigTreeConfigDataLoader,\
org.springframework.boot.context.config.StandardConfigDataLoader

# Run Listeners
org.springframework.boot.SpringApplicationRunListener=\
org.springframework.boot.context.event.EventPublishingRunListener

# Error Reporters
org.springframework.boot.SpringBootExceptionReporter=\
org.springframework.boot.diagnostics.FailureAnalyzers

# Application Context Initializers
org.springframework.context.ApplicationContextInitializer=\
org.springframework.boot.context.ConfigurationWarningsApplicationContextInitializer,\
org.springframework.boot.context.ContextIdApplicationContextInitializer,\
org.springframework.boot.context.config.DelegatingApplicationContextInitializer,\
org.springframework.boot.rsocket.context.RSocketPortInfoApplicationContextInitializer,\
org.springframework.boot.web.context.ServerPortInfoApplicationContextInitializer

# Application Listeners
org.springframework.context.ApplicationListener=\
org.springframework.boot.ClearCachesApplicationListener,\
org.springframework.boot.builder.ParentContextCloserApplicationListener,\
org.springframework.boot.context.FileEncodingApplicationListener,\
......    
```

# 在解决方案中应用模块化技术

## 模块分类

- 前端模块
- 服务模块

## 服务模块的定义

- 在解决方案中，服务模块是用来解决特定技术问题或者适配特定业务场景的组件单元
- **服务模块**是面向`业务问题`和`业务场景`的维度进行划分和规划的，不是从技术维度进行划分
- 由以下几个部分构成
  - 接入接口：接入第三方资源或服务
  - 数据模型：面向特定的业务问题，该领域问题创建的数据模型
  - 业务逻辑：管理数据模型、适配业务需求、支撑服务接口的应用单元
  - 暴露的服务接口：面向外部消费者使用的接口，接口包含

![image-20210327141218065](60%E5%9F%BA%E4%BA%8ESpringBoot%E8%BF%9B%E8%A1%8C%E4%BA%A7%E5%93%81%E6%A8%A1%E5%9D%97%E5%8C%96%E5%BC%80%E5%8F%91.assets/image-20210327141218065.png)

## 模块的依赖管理

- 使用 maven 进行模块的依赖管理
- 模块依赖意味着模块之间接受服务接口的约定
- Form(名称和调用方式)-Fit(参数)-Function(返回值)，任何一方的改变将意味着服务不兼容
- 对于不兼容的服务，不能直接彼此使用，服务之间只能按照匹配的接口进行组合

## 模块组合为应用

- 服务以 jar 包的形式在应用中使用
- 通过配置来定义服务模块的使用方式和服务的内部行为
- 定义在数据模型和业务逻辑层的对象和接口，可以被以 API 的方式，被应用内的其它模块进行使用
- 暴露的服务接口以 endpoint 的形式对外部提供服务

# 模块化的目的和意义

- 应用是特定业务邻域内的应用，要解决的业务问题是固定的，业务场景是类似的，但是又有个性化的部分，这种场景是适合经行模块化的
- 模块化的目的是为了将应用拆分为支持不同业务场景的业务组件，
  - 当业务场景匹配度很高的时候，直接使用业务组件进行适配和支持；
  - 当业务场景符合之前组件设计的时候，可以通过配置来满足
  - 当业务场景能使用组件支持70%以上时，可以通过定制化版本来支持
  - 当业务场景无法用现有组件支持的时候，通过开发新的业务模块来支持，通过不断积累，收集业务场景的支撑能力

# 举例

