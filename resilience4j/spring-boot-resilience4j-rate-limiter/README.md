## Mastering Resilience4j Rate Limiter with Spring Boot: A Practical Guide
For complete understanding of Resilience4j Rate Limiter module and how we can use it inside the Spring Boot application you can checkout our blog.
<br/><br/>**Blog Link:** [Mastering Resilience4j Rate Limiter with Spring Boot: A Practical Guide](https://bootcamptoprod.com/resilience4j-rate-limiter)
<br/>
## spring-boot-resilience4j-rate-limiter
A simple app highlighting how we can implement rate limiter using Resilience4j in Spring Boot.

## App Overview
This is a simple app wherein we are fetching the movie details based on the movie id. The movie details are fetched from external service that is called using the Spring Rest Template. For simplicity, we have created a mock controller which acts as a external service for returning the movie details.

## Rate Limiter Scenarios
We have created a single controller endpoint which accepts movie id as path parameter and query parameter rateLimitType which accepts predefined set of values to mimic the different rate limiter examples.

### Acceptable Values

#### For Path Parameter - Movie Id
a. **1** or **2** - Mock controller returns valid movie information<br/>
b. **3** - Mock controller returns HTTP status code 404<br/>
c. **4** or **any other numeric value** - Mock controller returns null which leads to MovieNotFound Exception

#### For Query Parameter - rateLimitType
Different rate limiter instances are defined inside the application.yml. To mimic different rate limiting scenarios use:<br/>
a. **simple-rate-limit:** simpleRateLimit rate limiter instance will be triggered<br/>
b. **rate-limit-with-event-details:** rateLimiterEventsExample rate limiter instance will be triggered.<br/>
c. **rate-limit-with-fallback:** simpleRateLimit rate limiter instance will be triggered and fallback method logic will be executed in this case.<br/>
d. **rate-limit-with-custom-config:** customRateLimiterConfig rate limiter instance defined in RateLimiterConfiguration class will be triggered.<br/>

## cURL Commands
Check the application logs in order to get the better understanding of different rate limiter scenarios.

### 1. Simple Rate Limit
```
curl 'http://localhost:8080/movies/3?rateLimitType=simple-rate-limit'
```

### 2. Rate Limit with Fallback
```
curl 'http://localhost:8080/movies/1?rateLimitType=rate-limit-with-fallback'
```

### 3. Rate Limit with Custom Configuration
```
curl 'http://localhost:8080/movies/1?rateLimitType=rate-limit-with-custom-config'
```

### 4. Rate Limit with Event Details
```
curl 'http://localhost:8080/movies/1?rateLimitType=rate-limit-with-event-details'
```