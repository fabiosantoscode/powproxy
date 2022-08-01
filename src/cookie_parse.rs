use atoi::atoi;

/// Length of "pow_cchal=" and "pow_magic="
static COOKIE_LEN: usize = 10;

pub fn parse_cookies<'a>(source: &'a [u8]) -> Option<(&'a [u8], u32)> {
    let mut challenge: Option<&'a [u8]> = None;
    let mut magic: Option<u32> = None;

    for (i, window) in source.windows(COOKIE_LEN).enumerate() {
        if window == b"pow_cchal=" {
            challenge = Some(cut_cookie(&source[i + COOKIE_LEN..]));

            if magic.is_some() {
                break;
            }
        } else if window == b"pow_magic=" {
            let magic_no = cut_cookie(&source[i + COOKIE_LEN..]);
            magic = atoi::<u32>(magic_no);

            if challenge.is_some() && magic.is_some() {
                break;
            }
        }
    }

    Some((challenge?, magic?))
}

fn cut_cookie<'a>(input: &'a [u8]) -> &'a [u8] {
    if let Some(end_index) = input.iter().position(|c| *c == b';') {
        &input[0..end_index]
    } else {
        input
    }
}

#[test]
fn test_parse_cookies() {
    assert_eq!(
        parse_cookies(b"; pow_cchal=abcd; pow_magic=1234"),
        Some((&b"abcd"[0..4], 1234))
    );
}

#[test]
fn test_cut_cookie() {
    assert_eq!(cut_cookie(b""), &[]);
    assert_eq!(cut_cookie(b"1234"), &b"1234"[..]);
    assert_eq!(cut_cookie(b"1234; "), &b"1234"[..]);
}
