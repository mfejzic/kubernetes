#########################################################################################################
#                                              VPC Components                                           #
#########################################################################################################

# Create virtual private cloud
resource "aws_vpc" "vpc" {
  cidr_block = var.vpc_cidr
  tags = {
    "Name"                              = "vpc${var.environment}"
    "kubernetes.io/cluster/eks-cluster" = "owned"
  }
}

# ------------------------------------- VPC endpoints -------------------------------------#
resource "aws_vpc_endpoint" "ec2_endpoint" {
  vpc_id             = aws_vpc.vpc.id
  service_name       = "com.amazonaws.us-east-1.ec2"
  security_group_ids = [aws_security_group.alb_sg.id] # Allow traffic from ALB security group

  vpc_endpoint_type = "Interface"

  tags = {
    Name = "ec2-endpoint"
  }
}
resource "aws_vpc_endpoint" "ecr_endpoint" {
  vpc_id       = aws_vpc.vpc.id
  service_name = "com.amazonaws.us-east-1.ecr.dkr"

  security_group_ids = [aws_security_group.alb_sg.id] # Allow traffic from ALB security group

  vpc_endpoint_type = "Interface"

  tags = {
    Name = "ecr-endpoint"
  }
}
resource "aws_vpc_endpoint" "alb_endpoint" {
  vpc_id             = aws_vpc.vpc.id
  service_name       = "com.amazonaws.us-east-1.elasticloadbalancing"
  security_group_ids = [aws_security_group.alb_sg.id] # Allow traffic from ALB security group
  vpc_endpoint_type  = "Interface"

  tags = {
    Name = "alb_endpoint"
  }
}

resource "aws_network_acl" "nacl" {
  vpc_id = aws_vpc.vpc.id
}

# ------------------------------------- NACL and rule associations -------------------------------------#
resource "aws_network_acl_rule" "allow_all_inbound" {
  rule_number    = 100
  network_acl_id = aws_network_acl.nacl.id
  rule_action    = var.rule_action_allow
  protocol       = "-1"
  cidr_block     = var.allow_all_cidr
  from_port      = 0
  to_port        = 65535
  egress         = false
}
resource "aws_network_acl_rule" "allow_all_outbound" {
  rule_number    = 100
  network_acl_id = aws_network_acl.nacl.id
  rule_action    = var.rule_action_allow
  protocol       = "-1"
  cidr_block     = var.allow_all_cidr
  from_port      = 0
  to_port        = 65535
  egress         = true
}

resource "aws_network_acl_association" "nacl_public_association" {
  for_each       = aws_subnet.public_subnets
  network_acl_id = aws_network_acl.nacl.id
  subnet_id      = aws_subnet.public_subnets[each.key].id
}
resource "aws_network_acl_association" "nacl_private_association" {
  for_each       = aws_subnet.private_subnets
  network_acl_id = aws_network_acl.nacl.id
  subnet_id      = aws_subnet.private_subnets[each.key].id
}

# ------------------------------------- Available zones in current region -------------------------------------#
data "aws_availability_zones" "available" {
  state = "available"
}

# ------------------------------------- private/public subnets -------------------------------------#
resource "aws_subnet" "public_subnets" {
  for_each                = var.public_subnets
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, each.value + 100)
  availability_zone       = tolist(data.aws_availability_zones.available.names)[each.value]
  map_public_ip_on_launch = true

  tags = {
    Name                                = "${each.key}"
    "kubernetes.io/role/elb"            = "1"
    "kubernetes.io/cluster/eks-cluster" = "owned"
  }
}
resource "aws_subnet" "private_subnets" {
  for_each                = var.private_subnets
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, each.value)
  availability_zone       = tolist(data.aws_availability_zones.available.names)[each.value]
  map_public_ip_on_launch = false

  tags = {
    "Name" = "${each.key}"
    "kubernetes.io/role/elb"            = "1"
    "kubernetes.io/cluster/eks-cluster" = "owned"
  }
}

# Create internet gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "igw${var.environment}"
  }
}

#Create elastic IP for NAT Gateway/nat gateway needs eip
resource "aws_eip" "eip_1" {
  provider   = aws.primary
  domain     = "vpc"
  depends_on = [aws_internet_gateway.igw]
  tags = {
    Name = "eip${var.environment}"
  }
}
resource "aws_eip" "eip_2" {
  provider   = aws.primary
  domain     = "vpc"
  depends_on = [aws_internet_gateway.igw]
  tags = {
    Name = "eip${var.environment}"
  }
}

# Create NAT Gateway for each public subnet
resource "aws_nat_gateway" "ngw_public_subnet_1" {
  depends_on    = [
  aws_subnet.public_subnets, 
  aws_internet_gateway.igw
  ]
  allocation_id = aws_eip.eip_1.id
  subnet_id     = aws_subnet.public_subnets["public_subnet_1"].id

  tags = {
    Name = "ngw_public_subnet_1${var.environment}"
  }
}
resource "aws_nat_gateway" "ngw_public_subnet_2" {
  depends_on    = [
  aws_subnet.public_subnets, 
  aws_internet_gateway.igw
  ]
  allocation_id = aws_eip.eip_2.id
  subnet_id     = aws_subnet.public_subnets["public_subnet_2"].id

  tags = {
    Name = "ngw_public_subnet_2${var.environment}"
  }
}

# Create public/private route tables
resource "aws_route_table" "public_rtb" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = var.allow_all_cidr
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "public_rtb${var.environment}"
  }
}
resource "aws_route_table" "private_rtb_1" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = var.allow_all_cidr
    //gateway_id = aws_internet_gateway.igw.id
    nat_gateway_id = aws_nat_gateway.ngw_public_subnet_1.id
  }

  tags = {
    Name = "private_rtb_1${var.environment}"
  }
}
resource "aws_route_table" "private_rtb_2" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = var.allow_all_cidr
    //gateway_id = aws_internet_gateway.igw.id
    nat_gateway_id = aws_nat_gateway.ngw_public_subnet_2.id
  }

  tags = {
    Name = "private_rtb_2${var.environment}"
  }
}

# Associate route tables with subnets
resource "aws_route_table_association" "public_rta" {
  depends_on     = [aws_subnet.public_subnets]
  for_each       = aws_subnet.public_subnets
  subnet_id      = aws_subnet.public_subnets[each.key].id
  route_table_id = aws_route_table.public_rtb.id
}
resource "aws_route_table_association" "private_rta_1" {
  depends_on     = [aws_subnet.private_subnets]
  subnet_id      = aws_subnet.private_subnets["private_subnet_1"].id
  route_table_id = aws_route_table.private_rtb_1.id
}
resource "aws_route_table_association" "private_rta_2" {
  depends_on     = [aws_subnet.private_subnets]
  subnet_id      = aws_subnet.private_subnets["private_subnet_2"].id
  route_table_id = aws_route_table.private_rtb_2.id
}


######################################################################################################
#                                           Security groups                                          #
######################################################################################################


resource "aws_security_group" "bastion_sg" {
  name        = "bastion_sg"
  description = "Allow SSH inbound traffic"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allow_all_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.allow_all_cidr]
  }

  tags = {
    "Name" = "bastion_sg${var.environment}"
  }
}

# Create security group for load balancer
resource "aws_security_group" "alb_sg" {
  name        = "alb_sg"
  description = "Allow http/https inbound/outbound traffic for alb"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.allow_all_cidr]

  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.allow_all_cidr]
  }

  tags = {
    "Name" = "alb_sg${var.environment}"
  }
}

# resource "aws_security_group" "eks_sg" {
#   name        = "eks_sg"
#   description = "http/http for kubernetes containers"
#   vpc_id      = aws_vpc.vpc.id

#   ingress {
#     from_port   = 80
#     to_port     = 80
#     protocol    = "tcp"
#     cidr_blocks = [var.allow_all_cidr]

#     security_groups = [
#       aws_security_group.alb_sg.id,
#       aws_security_group.bastion_sg.id
#     ]
#   }

#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = [var.allow_all_cidr]
#   }

#   tags = {
#     "Name" = "eks_sg${var.environment}"
#   }
# }


#######################################################################################################
#                                            EC2 components                                           #
#######################################################################################################


# Create key pair / Store private key on local machine
resource "tls_private_key" "generated" {
  algorithm = "RSA"
  rsa_bits  = "2048"
}
resource "local_file" "generated" {
  content  = tls_private_key.generated.private_key_pem
  filename = var.local_private_key
}
resource "aws_key_pair" "keypair" {
  key_name   = var.keypair_name
  public_key = tls_private_key.generated.public_key_openssh
}

# Use latest ubuntu AMI
data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["zx_ubuntu22"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["334577349345"]
}

# Create a bastion host in each public subnet
resource "aws_instance" "bastion" {
  for_each                    = aws_subnet.public_subnets
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  vpc_security_group_ids      = [aws_security_group.bastion_sg.id]
  subnet_id                   = aws_subnet.public_subnets[each.key].id
  key_name                    = aws_key_pair.keypair.key_name
  associate_public_ip_address = true

  tags = {
    Name = "bastion_${each.key}${var.environment}"
  }

  # Display private/public IP's in text file
  provisioner "local-exec" {
    command = <<-EOT
      echo "${self.private_ip} >> private_ips_bastion.txt"
      echo "${self.public_ip} >> public_ips_bastion.txt"
    EOT
  }
}

# Create instances in private subnet 2 to run kubernetes containers 
# resource "aws_instance" "containers" {
#   ami                         = data.aws_ami.ubuntu.id
#   instance_type               = var.instance_type
#   vpc_security_group_ids      = [aws_security_group.eks_sg.id]
#   subnet_id                   = aws_subnet.private_subnets["private_subnet_2"].id
#   key_name                    = aws_key_pair.keypair.key_name
#   iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
#   associate_public_ip_address = false

#   tags = {
#     Name = "container_${var.environment}"
#   }

#   # Display private/public IP's in text file
#   provisioner "local-exec" {
#     command = <<-EOT
#       echo "${self.private_ip} >> private_ips_bastion.txt"
#       echo "${self.public_ip} >> public_ips_bastion.txt"
#     EOT
#   }
# }


##############################################################################################################
#                                        Load balancing + Launch template                                    #
##############################################################################################################


# Create application load balancer
resource "aws_lb" "alb" {
  name                       = "eks-alb"
  internal                   = false
  load_balancer_type         = "application"
  enable_deletion_protection = false
  ip_address_type            = "ipv4"
  enable_http2               = true

  security_groups = [
    aws_security_group.alb_sg.id
  ]

  subnets = [
    aws_subnet.public_subnets["public_subnet_1"].id,
    aws_subnet.public_subnets["public_subnet_2"].id
  ]

  tags = {
    Name = "eks-alb${var.environment}"

  }
}

# Create targer group for load balancer
resource "aws_lb_target_group" "ip_target_group_http" {
  name        = "ip-target-group-http"
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.vpc.id

  health_check {
    path                = "/health"
    port                = 80
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 30
    timeout             = 10
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }
}

# Create http listener in target group
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "redirect"
    target_group_arn = aws_lb_target_group.ip_target_group_http.arn
    redirect {
      port        = "80"
      protocol    = "HTTP"
      status_code = "HTTP_301"         # Define the desired HTTP status code
      host        = "www.fejzic37.com" # Set the desired host value
    }
  }
}

# Create listener rule to forward traffic to domain
resource "aws_lb_listener_rule" "http_rule" {
  provider     = aws.primary
  listener_arn = aws_lb_listener.http_listener.arn
  priority     = 2

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ip_target_group_http.arn
  }

  condition {
    host_header {
      values = ["www.fejzic37.com"]
    }
  }
}

# ------------------------------------- Create and attach launch template to worker node configuration-------------------------------------#

# Create launch template for auto scaling
resource "aws_launch_template" "launch_template" {
  name          = "eks-launch_template"
  instance_type = var.instance_type
  key_name      = var.keypair_name
  image_id      = data.aws_ami.ubuntu.id

  # iam_instance_profile {
  #   arn = aws_iam_instance_profile.ec2_profile.arn
  # }

  # vpc_security_group_ids = [
  #   aws_security_group.eks_sg.id
  # ]

  # depends_on = [ 
  #   aws_iam_instance_profile.ec2_profile
  #  ]

  tags = {
    "Name" = "eks-launch_template${var.environment}"
  }
}

# Create auto scaling group/ attach launch template
# resource "aws_autoscaling_group" "asg" {
#   name                      = "asg${var.environment}"
#   max_size                  = 3
#   min_size                  = 1
#   health_check_grace_period = 300
#   health_check_type         = "ELB"
#   desired_capacity          = 2
#   force_delete              = true
#   vpc_zone_identifier       = [aws_subnet.private_subnets["private_subnet_2"].id]

#   launch_template {
#     id      = aws_launch_template.launch_template.id
#     version = "$Latest"
#   }
# }


#######################################################################################################
#                                        Kubernetes Components                                        #
#######################################################################################################


resource "aws_eks_cluster" "eks" {
  name     = "eks-cluster"
  role_arn = aws_iam_role.master_role.arn

  vpc_config {
    subnet_ids = [
      aws_subnet.private_subnets["private_subnet_1"].id,
      aws_subnet.private_subnets["private_subnet_2"].id
    ]

    security_group_ids = [
      //aws_security_group.eks_sg.id,
      aws_security_group.bastion_sg.id,
      aws_security_group.alb_sg.id
    ]
  }

  depends_on = [
    aws_iam_role_policy_attachment.AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.AmazonEKSServicePolicy,
    aws_iam_role_policy_attachment.AmazonEKSVPCResourceController
  ]

  tags = {
    Name = "eks_cluster${var.environment}"
  }
}

resource "aws_eks_node_group" "eks" {
  cluster_name    = aws_eks_cluster.eks.name
  node_group_name = "node-group"
  node_role_arn   = aws_iam_role.worker_role.arn
  capacity_type   = "ON_DEMAND"

  subnet_ids = [aws_subnet.private_subnets["private_subnet_2"].id]

  launch_template {
    version = "1"
    id      = aws_launch_template.launch_template.id
  }

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }

  update_config {
    max_unavailable = 1
  }

  labels = {
    app = "app"
  }

  depends_on = [
    aws_iam_role_policy_attachment.AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.AmazonEC2ContainerRegistryReadOnly,
    aws_eks_addon.addon
  ]

  tags = {
    Name = "eks_node_group${var.environment}"
    "kubernetes.io/cluster/eks-cluster": "owned"
  }
}

resource "aws_eks_fargate_profile" "eks_fargate" {
  cluster_name           = aws_eks_cluster.eks.name
  fargate_profile_name   = "fargate"
  pod_execution_role_arn = aws_iam_role.fargate_role.arn
  subnet_ids             = [aws_subnet.private_subnets["private_subnet_1"].id]

  selector {
    namespace = "default"
    labels = {
      app = "app"
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.AmazonEKSFargatePodExecutionRolePolicy
  ]

  tags = {
    Name = "eks_fargate_${var.environment}"
    "kubernetes.io/cluster/eks-cluster": "owned"
  }
}

# Create AWS EKS addons
resource "aws_eks_addon" "addon" {
  count        = length(var.addons)
  cluster_name = aws_eks_cluster.eks.name
  addon_name   = var.addons[count.index]
}


##############################################################################################################
#                                                    IAM Roles                                               #
##############################################################################################################


# ------------------------------------- Create eks master role -------------------------------------#
resource "aws_iam_role" "master_role" {
  name = "eks-main-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = ["eks.amazonaws.com"]
        }
      }
    ]
  })
}
resource "aws_iam_role_policy_attachment" "AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.master_role.name
}
resource "aws_iam_role_policy_attachment" "AmazonEKSServicePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
  role       = aws_iam_role.master_role.name
}
resource "aws_iam_role_policy_attachment" "AmazonEKSVPCResourceController" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.master_role.name
}

# ------------------------------------- Create fargate role for serverless -------------------------------------#
resource "aws_iam_role" "fargate_role" {
  name = "eks-fargate-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = ["eks-fargate-pods.amazonaws.com"]
        }
      }
    ]
  })
}
resource "aws_iam_role_policy_attachment" "AmazonEKSFargatePodExecutionRolePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
  role       = aws_iam_role.fargate_role.name
}

# ------------------------------------- Create ec2 roles for worker nodes -------------------------------------#
resource "aws_iam_role" "worker_role" {
  name = "eks-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = ["ec2.amazonaws.com"]
        }
      }
    ]
  })
}
resource "aws_iam_role_policy_attachment" "AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.worker_role.name
}
resource "aws_iam_role_policy_attachment" "AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.worker_role.name
}
resource "aws_iam_role_policy_attachment" "AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.worker_role.name
}


############################################################################################################################
#                                                        Route 53                                                          #
############################################################################################################################


# Refer to current hosted zone in aws console
data "aws_route53_zone" "hosted_zone" {
  name         = var.domain_name
  private_zone = false
}

# Create primary and secondary alias with failover policy / secondary points to us-west-2 load balancer
resource "aws_route53_record" "primary_alias" {
  //provider = aws.primary
  zone_id = data.aws_route53_zone.hosted_zone.zone_id
  name    = "www.${data.aws_route53_zone.hosted_zone.name}"
  type    = "A"

  alias {
    name                   = aws_lb.alb.dns_name
    zone_id                = aws_lb.alb.zone_id
    evaluate_target_health = true
  }
  failover_routing_policy {
    type = "PRIMARY"
  }
  set_identifier  = "primary"
  health_check_id = aws_route53_health_check.primary.id
}

# Create health check for primary and secondary records
resource "aws_route53_health_check" "primary" {
  fqdn              = var.subdomain_name
  port              = 80
  type              = "HTTPS"
  request_interval  = 30
  failure_threshold = 3
  tags = {
    Name = "primary_health_check"
  }
}
