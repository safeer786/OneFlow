#!groovy

node 
{
   
    // AWS 
    def awsRegion="eu-central-1"
    
	// Print identity the AWS commands are running with
    awsIdentity()
    def awsEnvironments = ['PROD','DEV','CC','SBX']
    for (String awsEnvironment: awsEnvironments)
    {


		//Stack tags
		def owner = 'Owner=CO-IAM'
		def name = 'Name=CO-IAM-' + awsEnvironment
		def orgunit = 'OrgUnit=CloudOps'
		def user = 'user:Environment=' + awsEnvironment	

		//Print parameter
    	echo ('awsEnvironment: ' + awsEnvironment)
    	echo ('repo: ' + repo)

		def awsUser='AWS-'+ awsEnvironment.toUpperCase() //AWS IAM-USer credentials
		echo ('credentialId: ' + credentialId)
		echo ('AwsUser(Key): ' + awsUser)
		
		/////ROLES//////
		def roles =['PlatformOperator','ViewOnly','Network','InfrastructureOperator','IAM','Billing','AuditDirectConnect','AuditRoute53','Audit','AdminAccess','NetworkServiceRole','EIPWatchdog','FlowLogs']
	
		/////Policies//////
		def policies=['ADPMaintenance','CRPMaintenance','ViewOnly','IAMCfnAccess','CloudForms','NetworkServiceRole','EIPWatchdog','FlowLogs']
	
		/////Users//////
	
		//User stack settings
		def stackNameCloudFormsUser='AZD-IAM-USER-CLOUDFORMSUSER-' + awsEnvironment.toUpperCase()
	
	
		//Cloudformation user templates
		def cfnTemplateCloudFormsUser = 'Pipeline/User/IAMUser'+ 'CloudForms' +'.template'
	
	
	
		//Ouputs
    	def cfnOutputsRoles = null
		def cfnOutputsPolicies = null
		//HipChat variables
		def msg = ''
		def repo = 'https://github.developer.allianz.io/azdcloud-ops/aws-iam'
		def credentialId = 'tu-github'
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
				withAWS(region:awsRegion, credentials:awsUser) 
				{
					for(String policy: policies)
					{
						def cfnTemplate='Pipeline/Policies/IAMPolicy'+policy+'.template'
						def stackName='AZD-IAM-POLICY-'+policy.toUpperCase()+'-'+awsEnvironment.toUpperCase()
						cfnOutputsPolicies = cfnUpdate(stack:stackName, file:cfnTemplate, params:[], keepParams:[], tags:[owner,name,orgunit,user])
					}						
				}										
			}

			stage('Update Roles') 
			{			
				withAWS(region:awsRegion, credentials:awsUser) 
				{
					for(String role: roles)
					{
						def cfnTemplate='Pipeline/Roles/IAMRole'+role+'.template'
						def stackName='AZD-IAM-ROLE-'+role.toUpperCase()+'-' + awsEnvironment.toUpperCase()
						cfnOutputsRoles = cfnUpdate(stack:stackName, file:cfnTemplate, params:[], keepParams:[], tags:[owner,name,orgunit,user])
					}
				}	
			}
			
			stage('Update Users')
			{
				//CloudForms
				withAWS(region:awsRegion, credentials:awsUser) 
				{
					cfnOutputsRoles = cfnUpdate(stack:stackNameCloudFormsUser, file:cfnTemplateCloudFormsUser, params:[], keepParams:[], tags:[owner,name,orgunit,user])
					
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
		catch(e)
		{
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
}