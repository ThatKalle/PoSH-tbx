function New-FizzBuzzv1 {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [int]$length
    )

    $FizzCount = 0
    $BuzzCount = 0
    $FizzBuzzCount = 0
    
    For ($i=1; $i -le $length; $i++) {
        $isFizz = $false
        $isBuzz = $false
        $isFizzBuzz = $false
        $result = $i

        if (($i % 3) -eq 0) {
            $isFizz = $true
            $FizzCount ++
        }
        if (($i % 5) -eq 0) {
            $isBuzz = $true
            $BuzzCount ++
        }
        if ($isFizz -and $isBuzz) {
            $isFizzBuzz = $true
            $result = "FizzBuzz"
            $FizzBuzzCount ++
        }

        #resultTest
        if ($isFizz -and !($isBuzz)){
            $result = "Fizz"
        }
        if ($isBuzz -and !($isFizz)){
            $result = "Buzz"
        }
        
        Write-Host $result
    }
    Write-Host "Fizz: $($FizzCount)"
    Write-Host "Buzz: $($BuzzCount)"
    Write-Host "FizzBuzz: $($FizzBuzzCount)"

} ## END New-FizzBuzzv1

function New-FizzBuzzv2 {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [int]$length
    )

    $FizzCount = 0
    $BuzzCount = 0
    $FizzBuzzCount = 0
    
    For ($i=1; $i -le $length; $i++) {
        $output = ""
        if (($i % 3) -eq 0) {$output += "Fizz";$FizzCount ++}
        if (($i % 5) -eq 0) {$output += "Buzz";$BuzzCount ++}
        if ($output -eq "FizzBuzz") {$FizzBuzzCount ++}
        if ($output -eq "") {$output = $i}

        Write-Host $output
    }

    Write-Host "Fizz: $($FizzCount)"
    Write-Host "Buzz: $($BuzzCount)"
    Write-Host "FizzBuzz: $($FizzBuzzCount)"
    
} ## END New-FizzBuzzv2


#New-FizzBuzzv1 -length 100
New-FizzBuzzv2 -length 100
