package com.bootcamptoprod.rate.limiter.controller;

import com.bootcamptoprod.rate.limiter.entity.Movie;
import com.bootcamptoprod.rate.limiter.service.MovieService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/movies")
public class MovieController {

    private final Logger log = LoggerFactory.getLogger(MovieService.class);

    @Autowired
    private MovieService movieService;

    @GetMapping("/{id}")
    public ResponseEntity<Movie> getMovieById(@PathVariable String id, @RequestParam(defaultValue = "simple-rate-limit") String rateLimitType) {
        switch (rateLimitType) {
            case "simple-rate-limit" -> {
                log.info("Simple rate limit example");
                Movie movie = movieService.getMovieDetails(id);
                return ResponseEntity.ok(movie);
            }
            case "rate-limit-with-event-details" -> {
                log.info("Rate limit with event details example");
                Movie movie = movieService.getMovieDetailsWithRateLimiterEventDetails(id);
                return ResponseEntity.ok(movie);
            }
            case "rate-limit-with-fallback" -> {
                log.info("Rate limit with fallback example");
                Movie movie = movieService.getMovieDetailsWithFallback(id);
                return ResponseEntity.ok(movie);
            }
            case "rate-limit-with-custom-config" -> {
                log.info("Rate limit with custom config example");
                Movie movie = movieService.getMovieDetailsWithCustomRateLimiterConfig(id);
                return ResponseEntity.ok(movie);
            }
        }
        return null;
    }
}
