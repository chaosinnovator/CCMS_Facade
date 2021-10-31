CREATE TABLE IF NOT EXISTS `items` (
  `item_sku` INT NOT NULL UNIQUE PRIMARY KEY,
  `item_name_short` TINYTEXT NOT NULL,
  `item_name` TINYTEXT NOT NULL,
  `item_caption` TINYTEXT NOT NULL,
  `item_description` MEDIUMTEXT NOT NULL,
  `item_model` TINYTEXT NOT NULL,
  `item_upca` TINYTEXT NOT NULL,
  `item_upce` TINYTEXT NOT NULL,
  `item_ean13` TINYTEXT NOT NULL,
  `item_ean8` TINYTEXT NOT NULL,
  `item_sell_unit` TINYTEXT NOT NULL,
  `item_sell_qty` INT NOT NULL,
  `sell_tax_id` INT NOT NULL,
  `sell_group_id` INT NOT NULL,
  `category_id` INT NOT NULL,
  `brand_id` INT NOT NULL,
  `item_weight` INT NOT NULL,
  `item_bought` BOOL NOT NULL,
  `item_sold` BOOL NOT NULL,
  `item_inventoried` BOOL NOT NULL,
  `item_serialized` BOOL NOT NULL,
  `asset_account_id` INT,
  `expense_account_id` INT,
  `income_account_id` INT,
  `item_reorder_limit` INT NOT NULL,
  `item_reorder_qty` INT NOT NULL,
  `item_is_template` BOOL NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/* -- item brands -- */
CREATE TABLE IF NOT EXISTS `item_brands` (
  `brand_id` INT NOT NULL,
  `brand_name` TINYTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/* -- foreign keys -- */
ALTER TABLE `items` ADD CONSTRAINT `items_brand_id_item_brands_brand_id` FOREIGN KEY (`brand_id`) REFERENCES `item_brands`(`brand_id`);