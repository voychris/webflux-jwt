package webfluxjwt.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SampleController {

    @GetMapping("/api/sample")
    public String sample() {
        return "I'm secured";
    }
}
