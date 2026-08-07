package unsafe

import . "time"

func testWait() { <-After(1) }
