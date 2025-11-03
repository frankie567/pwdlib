from enum import Enum, auto

__version__: str

class Warning(Enum):
    StraightRowsOfKeysAreEasyToGuess = auto()
    ShortKeyboardPatternsAreEasyToGuess = auto()
    RepeatsLikeAaaAreEasyToGuess = auto()
    RepeatsLikeAbcAbcAreOnlySlightlyHarderToGuess = auto()
    ThisIsATop10Password = auto()
    ThisIsATop100Password = auto()
    ThisIsACommonPassword = auto()
    ThisIsSimilarToACommonlyUsedPassword = auto()
    SequencesLikeAbcAreEasyToGuess = auto()
    RecentYearsAreEasyToGuess = auto()
    AWordByItselfIsEasyToGuess = auto()
    DatesAreOftenEasyToGuess = auto()
    NamesAndSurnamesByThemselvesAreEasyToGuess = auto()
    CommonNamesAndSurnamesAreEasyToGuess = auto()

class Suggestion(Enum):
    UseAFewWordsAvoidCommonPhrases = auto()
    NoNeedForSymbolsDigitsOrUppercaseLetters = auto()
    AddAnotherWordOrTwo = auto()
    CapitalizationDoesntHelpVeryMuch = auto()
    AllUppercaseIsAlmostAsEasyToGuessAsAllLowercase = auto()
    ReversedWordsArentMuchHarderToGuess = auto()
    PredictableSubstitutionsDontHelpVeryMuch = auto()
    UseALongerKeyboardPatternWithMoreTurns = auto()
    AvoidRepeatedWordsAndCharacters = auto()
    AvoidSequences = auto()
    AvoidRecentYears = auto()
    AvoidYearsThatAreAssociatedWithYou = auto()
    AvoidDatesAndYearsThatAreAssociatedWithYou = auto()

class Feedback:
    warning: Warning | None
    suggestions: list[Suggestion]

class CrackTimesSeconds:
    offline_fast_hashing_1e10_per_second: float
    offline_slow_hashing_1e4_per_second: float
    online_no_throttling_10_per_second: float
    online_throttling_100_per_hour: float

class CrackTimesDisplay:
    offline_fast_hashing_1e10_per_second: str
    offline_slow_hashing_1e4_per_second: str
    online_no_throttling_10_per_second: str
    online_throttling_100_per_hour: str

class Entropy:
    """Result of a password strength check."""

    guesses: int
    """Estimated guesses needed to crack the password"""

    guesses_log10: float
    """Order of magnitude of `guesses`."""

    crack_times_seconds: CrackTimesSeconds
    """List of back-of-the-envelope crack time estimations based on a few scenarios."""

    crack_times_display: CrackTimesDisplay
    """Same as crack_times_seconds, with friendlier display string values."""

    score: int
    """
    Overall strength score from 0-4.
    Any score less than 3 should be considered too weak.
    """

    feedback: Feedback | None
    """Verbal feedback to help choose better passwords. Set when `score` <= 2."""

    calc_time: int
    """How long it took to calculate the answer."""

def zxcvbn(password: str, user_inputs: list[str] | None = None) -> Entropy:
    """
    Measure the strength of a password.

    Args:
        password: The password to check.
        user_inputs: Optional list of strings input by the user
        in other fields to match against the password.

    Returns:
        An `Entropy` object.
    """
    ...
