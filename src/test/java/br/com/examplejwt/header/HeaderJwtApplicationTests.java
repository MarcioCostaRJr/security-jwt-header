package br.com.examplejwt.header;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class HeaderJwtApplicationTests {

	private static final String API = "Api";

	@Test
	void contextLoads() {
		assertEquals("Api", API);
	}

}
