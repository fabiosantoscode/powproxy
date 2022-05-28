/** How many zeroes we expect on the hash coming from the client */
pub static DIFFICULTY_BITS: usize = 16;
pub static EXPIRY_SECONDS: u64 = 300;
pub static CHALLENGE_PAGE: &'static str = "
<!doctype html>
<meta charset=utf-8>
<script>
;(async () => {
    const getCookie = name =>
        document.cookie.split('; ').find(c => c.startsWith(name)).split('=').pop();
    const setCookie = (nameVal) => {
        document.cookie = nameVal + '; SameSite=Strict; Path=/; Max-Age=300';
    };

    const hexToNums = (hexString, nums = []) => {
        for (let i = 0; i < hexString.length; i += 2) {
            nums.push(parseInt(hexString.slice(i, i + 2), 16));
        }
        return new Uint8Array(nums);
    };

    const challenge = getCookie('pow_chal=');
    const bufView = new DataView(hexToNums(challenge, [0, 0, 0, 0]).buffer);

    console.time('pow time');
    for (;;) {
        const hash = new DataView(await crypto.subtle.digest('SHA-256', bufView.buffer));
        if (hash.getUint8(0) === 0 && hash.getUint8(1) === 0) {
            break;
        }

        bufView.setUint32(0, bufView.getUint32(0) + 1);
    }
    console.timeEnd('pow time');

    setCookie('pow_magic=' + bufView.getUint32(0));
    setCookie('pow_resp=' + challenge);
    location.reload();
})().catch(error => {
    console.error(error);
});
</script>
";
