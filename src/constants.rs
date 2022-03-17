/** How many zeroes we expect on the hash coming from the client */
pub static DIFFICULTY_BITS: usize = 16;
pub static EXPIRY_SECONDS: u64 = 300;
pub static CHALLENGE_PAGE: &'static str = "
<!doctype html>
<meta charset=utf-8>
<script>
    const getCookie = name =>
        document.cookie.split('; ').find(c => c.startsWith(name + '=')).split('=').pop();

    const hexToNums = hexString => {
        let bytes = []
        for (let i = 0; i < hexString.length; i += 2) {
            bytes.push(parseInt(hexString.slice(i, i + 2), 16))
        }
        return bytes
    }

    const challenge = getCookie('pow_chal');

    async function do_challenge() {
        const bufView = new DataView(new Uint8Array([0, 0, 0, 0, ...hexToNums(challenge)]).buffer);
        let digested;

        console.time('pow time');
        for (;;) {
            digested = new DataView(await crypto.subtle.digest('SHA-256', bufView.buffer));

            if (
                digested.getUint8(0, false) === 0
                && digested.getUint8(1, false) === 0
            ) {
                break;
            }

            bufView.setUint32(0, bufView.getUint32(0, false) + 1, false)
        }
        console.timeEnd('pow time');
        return bufView.getUint32(0, false);
    }

    do_challenge().then(
        magic => {
            document.cookie = `pow_magic=${magic}; SameSite=Strict; Path=/; Max-Age=300`;
            document.cookie = `pow_resp=${challenge}; SameSite=Strict; Path=/; Max-Age=300`;
            location.reload();
        },
        e => console.error(e)
    );
</script>
";
