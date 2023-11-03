package com.bootcamptoprod.rate.limiter.service;

import com.bootcamptoprod.rate.limiter.client.MovieApiClient;
import com.bootcamptoprod.rate.limiter.entity.Movie;
import io.github.resilience4j.ratelimiter.RateLimiterRegistry;
import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;

@Service
public class MovieService {

    private final Logger log = LoggerFactory.getLogger(MovieService.class);

    @Autowired
    private RateLimiterRegistry registry;

    @Autowired
    private MovieApiClient movieApiClient;


    @RateLimiter(name = "simpleRateLimit")
    public Movie getMovieDetails(String movieId) {
        return fetchMovieDetails(movieId);
    }

    @RateLimiter(name = "rateLimiterEventsExample")
    public Movie getMovieDetailsWithRateLimiterEventDetails(String movieId) {
        return fetchMovieDetails(movieId);
    }

    @RateLimiter(name = "simpleRateLimit", fallbackMethod = "getMovieDetailsFallbackMethod")
    public Movie getMovieDetailsWithFallback(String movieId) {
        return fetchMovieDetails(movieId);
    }

    @RateLimiter(name = "customRateLimiterConfig")
    public Movie getMovieDetailsWithCustomRateLimiterConfig(String movieId) {
        return fetchMovieDetails(movieId);
    }

    private Movie fetchMovieDetails(String movieId) {
        Movie movie = null;
        try {
            movie = movieApiClient.getMovieDetails(movieId);
        } catch (HttpServerErrorException httpServerErrorException) {
            log.error("Received HTTP server error exception while fetching the movie details. Error Message: {}", httpServerErrorException.getMessage());
            throw httpServerErrorException;
        } catch (HttpClientErrorException httpClientErrorException) {
            log.error("Received HTTP client error exception while fetching the movie details. Error Message: {}", httpClientErrorException.getMessage());
            throw httpClientErrorException;
        } catch (ResourceAccessException resourceAccessException) {
            log.error("Received Resource Access exception while fetching the movie details.");
            throw resourceAccessException;
        } catch (Exception exception) {
            log.error("Unexpected error encountered while fetching the movie details");
            throw exception;
        }
        return movie;
    }

    private Movie getMovieDetailsFallbackMethod(String movieId, RequestNotPermitted requestNotPermitted) {
        log.info("Fallback method called.");
        log.info("RequestNotPermitted exception message: {}", requestNotPermitted.getMessage());
        return new Movie("Default", "N/A", "N/A", 0.0);
    }

    @PostConstruct
    public void postConstruct() {
        io.github.resilience4j.ratelimiter.RateLimiter.EventPublisher eventPublisher = registry
                .rateLimiter("rateLimiterEventsExample")
                .getEventPublisher();

        eventPublisher.onEvent(event -> System.out.println("Simple Rate Limit - On Event. Event Details: " + event));
        eventPublisher.onSuccess(event -> System.out.println("Simple Rate Limit - On Success. Event Details: " + event));
        eventPublisher.onFailure(event -> System.out.println("Simple Rate Limit - On Failure. Event Details: " + event));

    }

}
