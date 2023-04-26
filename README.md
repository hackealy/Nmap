Nmap é uma ferramenta de código aberto utilizada para varredura de rede e descoberta de hosts e serviços. Algumas das técnicas de port scanning suportadas pelo Nmap são:

TCP SYN scan (-sS): Este é um método comum de port scanning que envia um pacote SYN para a porta de destino e aguarda a resposta. Se a porta estiver aberta, o sistema responderá com um pacote SYN/ACK, caso contrário, o sistema responderá com um pacote RST.

TCP connect scan (-sT): Esta técnica envia um pacote TCP de conexão à porta de destino. Se a porta estiver aberta, o sistema responderá com um pacote SYN/ACK, caso contrário, o sistema responderá com um pacote RST.

TCP ACK scan (-sA): Nesta técnica, o Nmap envia um pacote ACK para a porta de destino. Se a porta estiver aberta, o sistema responderá com um pacote RST/ACK, caso contrário, o sistema responderá com um pacote RST.

TCP Window scan (-sW): Esta técnica envia um pacote TCP com uma janela de tamanho zero à porta de destino. Se a porta estiver aberta, o sistema responderá com um pacote TCP com uma janela de tamanho zero, caso contrário, o sistema responderá com um pacote RST.

UDP scan (-sU): Esta técnica é usada para varreduras de porta UDP. Ela envia um pacote UDP à porta de destino e aguarda uma resposta. Se a porta estiver aberta, o sistema responderá com um pacote UDP, caso contrário, o sistema não responderá.

SCTP INIT scan (-sY): Esta técnica é usada para port scanning em protocolos SCTP (Stream Control Transmission Protocol). O Nmap envia um pacote INIT à porta de destino e aguarda uma resposta. Se a porta estiver aberta, o sistema responderá com um pacote INIT ACK, caso contrário, o sistema responderá com um pacote ABORT.

IP protocol scan (-sO): Esta técnica é usada para varreduras de protocolo IP. Ela envia um pacote IP à porta de destino e aguarda uma resposta. Se o protocolo estiver disponível, o sistema responderá com um pacote ICMP, caso contrário, o sistema responderá com um pacote ICMP informando que o protocolo não está disponível.

Existem outras técnicas de port scanning disponíveis no Nmap, mas essas são algumas das mais comuns.

Para executar um port scan com o Nmap, siga estes passos:

Instale o Nmap em seu sistema operacional, se ainda não o tiver instalado.

Abra um terminal ou prompt de comando, dependendo do seu sistema operacional.

Digite o seguinte comando:

 # nmap [opções] alvo

Substitua "opções" pelas opções de varredura que você deseja usar (por exemplo, -sS para TCP SYN scan, -sU para UDP scan, etc.), e "alvo" pelo endereço IP ou nome de domínio do host que você deseja varrer.

Aguarde até que a varredura seja concluída. O Nmap mostrará uma lista de portas abertas no host alvo e os serviços associados a essas portas.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------

Identifique o endereço IP ou nome de domínio do host que você deseja varrer. Suponha que o endereço IP do host seja 192.168.1.100.

Abra um terminal ou prompt de comando e digite o seguinte comando:

 # nmap -A -T4 192.168.1.100

Isso irá executar uma varredura completa no host, usando o perfil de agressividade -A e o nível de velocidade -T4. A opção -A permite que o Nmap execute uma série de testes para descobrir informações sobre o sistema operacional, serviços e versões instalados no host, enquanto a opção -T4 define o nível de velocidade da varredura.

Aguarde até que a varredura seja concluída. Isso pode levar algum tempo, dependendo da velocidade do host e do perfil de varredura que você escolheu.

Analise os resultados da varredura. O Nmap exibirá uma lista de portas abertas no host, junto com os serviços e versões associados a essas portas. Além disso, o Nmap também fornecerá informações sobre o sistema operacional e outras vulnerabilidades conhecidas que podem estar presentes no host.

Use as informações coletadas na varredura para analisar e avaliar a segurança do host. Identifique possíveis vulnerabilidades e tome medidas para corrigi-las, se necessário.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------

Após encontrar os serviços em uma varredura com o Nmap, existem algumas opções disponíveis para analisar possíveis vulnerabilidades:

Verifique se o serviço está atualizado: Se o serviço encontrado estiver desatualizado, ele pode estar vulnerável a ataques conhecidos. Verifique se há atualizações disponíveis para o serviço e certifique-se de que a versão atual esteja instalada no host.

Use scripts NSE: O Nmap possui uma biblioteca de scripts NSE (Nmap Scripting Engine) que podem ajudar a identificar vulnerabilidades em serviços. Executar scripts do sistema operacional

Use o serviço Vulners.com: O Vulners.com é um banco de dados de vulnerabilidades e exploits que pode ser integrado ao Nmap para verificar se o serviço encontrado está vulnerável a ataques conhecidos.

Verifique se há vulnerabilidades conhecidas no serviço: Procure em sites de segurança e bancos de dados de vulnerabilidades conhecidas para verificar se o serviço encontrado é vulnerável a alguma exploração específica.

Execute outras ferramentas de verificação de vulnerabilidades: Além do Nmap, existem outras ferramentas de verificação de vulnerabilidades que podem ser usadas para verificar se um serviço está vulnerável a ataques conhecidos.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------

Os scripts NSE (Nmap Scripting Engine) são uma ferramenta poderosa que podem ser usados com o Nmap para executar testes automatizados e verificar possíveis vulnerabilidades em sistemas. Aqui está um exemplo de como usar scripts NSE no Nmap:

O parâmetro é bem simples de ser utilizado, na verdade é só chamar o script com o parâmetro --script

 # nmap -sS -sC -Pn --script vuln <IP do alvo>  
 
Existe um script muito legal que procura somente os exploits, diferente do script acima que faz vários testes consecutivos. 'Pow, já sei que é vulnerável', então use o script 'exploit'.
 
  # nmap -Pn -sS -sC --script exploit <IP do alvo>

Identifique o serviço que deseja verificar vulnerabilidades. Por exemplo, o serviço HTTP em um endereço IP específico:

  # nmap -sV --script=http-vuln-cve2017-5638 <IP do alvo>

Este comando irá verificar se o servidor HTTP está vulnerável à vulnerabilidade CVE-2017-5638.

Verifique todos os scripts disponíveis com a palavra-chave "http":

  # nmap --script-help "http-*"

Este comando irá listar todos os scripts disponíveis que possuem a palavra-chave "http".

Execute um script específico com o parâmetro -sC:

 # nmap -sV -sC --script=http-shellshock <IP do alvo>

Este comando irá executar o script "http-shellshock" que verifica a vulnerabilidade Shellshock em servidores HTTP.

Execute vários scripts em uma única linha de comando:

 # nmap -sV --script=http-enum,http-shellshock,http-vuln-cve2017-5638 <IP do alvo>

Este comando irá executar três scripts diferentes em uma única linha de comando para verificar vulnerabilidades em servidores HTTP.

É importante lembrar que a execução de scripts NSE pode ser um processo demorado e pode consumir muitos recursos do sistema. Além disso, alguns scripts podem ser muito intrusivos e podem levar a uma queda ou mau funcionamento do serviço alvo. Portanto, use scripts NSE com cuidado e certifique-se sempre de ter permissão do proprietário do sistema antes de executá-los.

Aqui estão alguns exemplos de scripts que podem ser usados para esse propósito:

http-vuln-cve2017-5638: Este script verifica se o servidor HTTP está vulnerável à vulnerabilidade CVE-2017-5638 que permite a remota execução de código.
smb-vuln-ms17-010: Este script verifica se um host Windows está vulnerável ao exploit EternalBlue que permite a execução remota de código.

ssl-heartbleed: Este script verifica se um servidor OpenSSL está vulnerável à vulnerabilidade Heartbleed que permite a leitura de memória do servidor.

ftp-vuln-cve2010-4221: Este script verifica se um servidor FTP está vulnerável à vulnerabilidade CVE-2010-4221 que permite a escalada de privilégios.

dns-zone-transfer: Este script verifica se um servidor DNS está configurado para permitir transferências de zona, o que pode levar à divulgação de informações confidenciais.

ssh-brute: Este script verifica a força das senhas em contas SSH para determinar se elas são fracas e vulneráveis a ataques de força bruta.

mysql-vuln-cve2012-2122: Este script verifica se um servidor MySQL está vulnerável à vulnerabilidade CVE-2012-2122 que permite a escalada de privilégios.

http-sql-injection: Este script verifica se um servidor HTTP é vulnerável a ataques de injeção SQL.
