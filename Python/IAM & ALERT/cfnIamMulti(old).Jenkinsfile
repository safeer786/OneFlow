#!groovy

node 
{
   
    // AWS 
    def awsRegion="eu-central-1"
    
	// Print identity the AWS commands are running with
    awsIdentity()

	//Stack tags
	def owner = 'Owner=CO-IAM'
	def name = 'Name=CO-IAM-' + awsEnvironment
	def orgunit = 'OrgUnit=CloudOps'
	def user = 'user:Environment=' + awsEnvironment	

	//Print parameter
    echo ('awsEnvironment: ' + awsEnvironment)
    echo ('repo: ' + repo)

	def awsUser='AWS-MT-'+ awsEnvironment.toUpperCase() + '-IAM' //AWS IAM-USer credentials
	echo ('credentialId: ' + credentialId)
	echo ('AwsUser(Key): ' + awsUser)
		
	/////ROLES//////
	def roles=["PlatformOperator","Network","InfrastructureOperator","IAM","Billing","AuditDirectConnect","AuditRoute53","Audit","AdminAccess","NetworkServiceRole","ServiceDeveloper", "FlowLogs"]
    def rolePath = 	'IAM/Roles/IAMRole'

	/////Policies//////
	def policies=["PlatformOperator","ServiceDeveloper","NetworkServiceRole","FlowLogs" ]
    def policyPath ='IAM/Policies/IAMPolicy'

	
	
	
	
	//Ouputs
    def cfnOutputsRoles = null
	def cfnOutputsPolicies = null
	//HipChat variables
	def msg = ''
	def commitChangeset = ''
	def commitMsg = ''
	def commit1 = ''
	def counter = 0

	
	try
	{
	
		stage('Checkout from git') 
		{
			git branch: 'master', credentialsId: credentialId, url: repo	 
			 
			commitChangeset = sh(returnStdout: true, script: 'git diff-tree --no-commit-id --name-status -r HEAD').split()
		
			for( String values : commitChangeset )
			{
				if ( counter % 2 == 0 ) 
				{
					commitMsg = commitMsg  +"<br>["+ (values)+ "]";
				} 
				else 
				{
					commitMsg = commitMsg  +"   "+ (values);
				}
				counter = counter +1
			}
		}

		
			stage('Update Policies') 
			{
			
				//Update All Policies

				withAWS(region:awsRegion, credentials:awsUser) 
					{
						for(String policy : policies)
						{
							def stackName='AZD-CO-IAM-POLICY-'+policy.toUpperCase()+'-' + awsEnvironment.toUpperCase()
							def cfnPolicyTemplate = policyPath + policy +'.template'	
							cfnOutputsPolicies = cfnUpdate(stack:stackName, file:cfnPolicyTemplate, params:[], keepParams:[], tags:[owner,name,orgunit,user])	
						}				
					}			
			} 
			
			
			stage('Update Roles') 
			{
				//Update All ROles
				withAWS(region:awsRegion, credentials:awsUser) 
				{
						for (String role : roles) 
						{
 							def stackName='AZD-CO-IAM-ROLE-'+ role.toUpperCase() +'-' + awsEnvironment.toUpperCase()
 							def cfnRoleTemplate= rolePath +role+'.template'
 							cfnOutputsRoles = cfnUpdate(stack:stackName, file:cfnRoleTemplate, params:[], keepParams:[], tags:[owner,name,orgunit,user])	
						}							
						
				}
				
			}	
			
			stage('SendNotifications') 
			{
				hipchatSend color: 'GREEN', 
				token:'xS5niEACKma31yTIOzpHvuDUH9dCBmCZAUMftePi', 
				failOnError: true, 
				message: 'Es wurde eine Änderung am AWS-IAM im ' + awsEnvironment.toUpperCase() + '-Account durchgeführt. folgende Dateien haben sich verändert:  ' + commitMsg  + "<br> Mehr Informationen zum AWS-IAM finden Sie auf unserem <a href='https://ind-wiki.allianz.de.awin/pages/viewpage.action?pageId=854430267'>Wiki</a>" , 
				notify: true,  
				room: 'CloudOps - Jenkins deployments', 
				server: 'hipchat.azd.io',
				textFormat: true, 
				v2enabled: true

			}
	
	}
		catch(e){
        hipchatSend color: 'RED', 
		token:'xS5niEACKma31yTIOzpHvuDUH9dCBmCZAUMftePi', 
		failOnError: true, 
		message: 'Der IAM-Jenkinsjob für:' + awsEnvironment.toUpperCase() + ' ist nicht Reibungslos durchgelaufen. Fehler: ' + e.toString(), 
		notify: true,  
		room: 'CloudOps - Jenkins deployments', 
		server: 'hipchat.azd.io',
		v2enabled: true
                }

}