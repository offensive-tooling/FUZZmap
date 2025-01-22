## fuzzmap

### install
`dev install` pip3 install -e .

🔧 도구로 사용하는 경우:

    fuzzmap -t http://testphp.vulnweb.com/listproducts.php -m get -p cat
    fuzzmap -t http://testphp.vulnweb.com/listproducts.php -m get -p cat,test
    fuzzmap -t http://testphp.vulnweb.com/listproducts.php -m post -p cat
    fuzzmap -t http://testphp.vulnweb.com/listproducts.php -m post -p cat,test
    fuzzmap -t http://testphp.vulnweb.com/listproducts.php -rp

🐍 모듈로 사용하는 경우:
    import asyncio
    from fuzzmap import Controller

    async def main():
        fm = Controller(target="http://testphp.vulnweb.com",method="GET",param="cat")
        results = await fm.async_run()
        print(results)

        fm = Controller(target="http://testphp.vulnweb.com",recon_param=True)
        results = await fm.async_run()
        print(results)

    asyncio.run(main())

⚙️  Options:

    -t, --target    🎯 Target URL to scan
    -m, --method    📡 HTTP method (GET/POST)
    -p, --param     🔍 Parameters to test (comma separated)
    -rp, --recon    🔎 Enable parameter reconnaissance
    -v, --verbose   📝 Enable verbose output
    -h, --help      ℹ️  Show this help message

🔔 Note: Use responsibly and only on authorized targets